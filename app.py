import os
import sqlite3
import smtplib
import ssl
import secrets
import hashlib
import json
from datetime import date, datetime, timedelta
from email.message import EmailMessage
from io import BytesIO
from typing import Dict, List, Optional, Tuple

import pandas as pd
import requests
import streamlit as st

APP_TITLE = "SRB Solar Verification App"
DB_PATH = "users.db"
RUNS_DIR = "runs"
REQUEST_TIMEOUT = 90
DEFAULT_OUTPUT_NAME = "srb_solar_verification_output.xlsx"
PVGIS_BASE_URL = "https://re.jrc.ec.europa.eu/api/v5_3/seriescalc"
NASA_BASE_URL = "https://power.larc.nasa.gov/api/temporal/hourly/point"
OPEN_METEO_ARCHIVE_URL = "https://archive-api.open-meteo.com/v1/archive"

PVGIS_DB_YEAR_LIMITS = {
    "PVGIS-SARAH2": (2005, 2020),
    "PVGIS-SARAH3": (2005, 2023),
    "PVGIS-ERA5": (2005, 2023),
}

NASA_PARAMETER_LABELS = {
    "ALLSKY_SFC_SW_DWN": "GHI",
    "CLRSKY_SFC_SW_DWN": "GHI clear sky",
    "ALLSKY_SFC_SW_DNI": "DNI",
    "ALLSKY_SFC_SW_DIFF": "DHI",
    "T2M": "T aria 2m",
    "WS10M": "Vento 10m",
}

OPEN_METEO_VARIABLE_LABELS = {
    "global_tilted_irradiance": "GTI - Irraggiamento globale sul piano inclinato",
    "shortwave_radiation": "GHI - Irraggiamento globale orizzontale",
    "direct_normal_irradiance": "DNI - Irraggiamento normale diretto",
    "diffuse_radiation": "DHI - Irraggiamento diffuso orizzontale",
    "temperature_2m": "Temperatura aria 2 m",
    "wind_speed_10m": "Velocità vento 10 m",
}

OPEN_METEO_MIN_REQUIRED = [
    "global_tilted_irradiance",
    "temperature_2m",
]

OPEN_METEO_RECOMMENDED_DEFAULT = [
    "global_tilted_irradiance",
    "temperature_2m",
    "wind_speed_10m",
    "shortwave_radiation",
    "direct_normal_irradiance",
    "diffuse_radiation",
]

TECH_TEMP_COEFF = {
    "crystSi": -0.0040,
    "CIS": -0.0031,
    "CdTe": -0.0025,
    "Unknown": -0.0040,
}


# ----------------------------
# Authentication
# ----------------------------
def hash_password(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return f"{salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    salt, expected = stored.split("$", 1)
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000).hex()
    return secrets.compare_digest(candidate, expected)


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    os.makedirs(RUNS_DIR, exist_ok=True)
    conn = get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            plant_code TEXT NOT NULL,
            weather_source TEXT NOT NULL,
            percentile INTEGER NOT NULL,
            run_created_at TEXT NOT NULL,
            output_filename TEXT NOT NULL,
            output_path TEXT NOT NULL,
            expected_energy_total_kwh REAL,
            measured_energy_total_kwh REAL,
            mean_deviation_pct REAL,
            hours_with_measurements INTEGER
        )
        """
    )
    conn.commit()

    existing = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    if existing == 0:
        admin_username = os.getenv("BOOTSTRAP_ADMIN_USERNAME", "admin")
        admin_email = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "admin@example.com")
        admin_password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "admin123!")
        conn.execute(
            "INSERT INTO users (username, email, password_hash, is_admin, created_at) VALUES (?, ?, ?, 1, ?)",
            (admin_username, admin_email, hash_password(admin_password), datetime.utcnow().isoformat()),
        )
        conn.commit()
    conn.close()


def authenticate(username: str, password: str) -> Optional[Dict]:
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if row and verify_password(password, row["password_hash"]):
        return dict(row)
    return None


def list_users() -> pd.DataFrame:
    conn = get_conn()
    df = pd.read_sql_query(
        "SELECT id, username, email, is_admin, created_at FROM users ORDER BY username",
        conn,
    )
    conn.close()
    return df


def create_user(username: str, email: str, password: str, is_admin: bool = False) -> None:
    conn = get_conn()
    conn.execute(
        "INSERT INTO users (username, email, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?, ?)",
        (username, email, hash_password(password), int(is_admin), datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def update_user(user_id: int, username: str, email: str, is_admin: bool, password: str = "") -> None:
    conn = get_conn()
    current = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if current is None:
        conn.close()
        raise ValueError("Utente non trovato.")

    if password.strip():
        conn.execute(
            "UPDATE users SET username = ?, email = ?, is_admin = ?, password_hash = ? WHERE id = ?",
            (username, email, int(is_admin), hash_password(password), user_id),
        )
    else:
        conn.execute(
            "UPDATE users SET username = ?, email = ?, is_admin = ? WHERE id = ?",
            (username, email, int(is_admin), user_id),
        )
    conn.commit()
    conn.close()


def delete_user(user_id: int, acting_user_id: int) -> None:
    if user_id == acting_user_id:
        raise ValueError("Non puoi cancellare l'utenza con cui sei connesso.")
    conn = get_conn()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def save_run_record(username: str, plant_code: str, weather_source: str, percentile: int, output_filename: str, output_bytes: bytes, kpi_df: pd.DataFrame) -> str:
    os.makedirs(RUNS_DIR, exist_ok=True)
    output_path = os.path.join(RUNS_DIR, output_filename)
    with open(output_path, "wb") as f:
        f.write(output_bytes)

    first = kpi_df.iloc[0].to_dict() if not kpi_df.empty else {}
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO runs (username, plant_code, weather_source, percentile, run_created_at, output_filename, output_path,
                          expected_energy_total_kwh, measured_energy_total_kwh, mean_deviation_pct, hours_with_measurements)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            username,
            plant_code,
            weather_source,
            int(percentile),
            datetime.utcnow().isoformat(),
            output_filename,
            output_path,
            first.get("expected_energy_total_kwh"),
            first.get("measured_energy_total_kwh"),
            first.get("mean_deviation_pct"),
            first.get("hours_with_measurements"),
        ),
    )
    conn.commit()
    conn.close()
    return output_path


def list_runs(username: Optional[str] = None) -> pd.DataFrame:
    conn = get_conn()
    if username:
        df = pd.read_sql_query(
            "SELECT id, username, plant_code, weather_source, percentile, run_created_at, output_filename, expected_energy_total_kwh, measured_energy_total_kwh, mean_deviation_pct, hours_with_measurements FROM runs WHERE username = ? ORDER BY run_created_at DESC",
            conn,
            params=(username,),
        )
    else:
        df = pd.read_sql_query(
            "SELECT id, username, plant_code, weather_source, percentile, run_created_at, output_filename, expected_energy_total_kwh, measured_energy_total_kwh, mean_deviation_pct, hours_with_measurements FROM runs ORDER BY run_created_at DESC",
            conn,
        )
    conn.close()
    return df


def get_run_file_path(run_id: int) -> Optional[str]:
    conn = get_conn()
    row = conn.execute("SELECT output_path FROM runs WHERE id = ?", (run_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    return row["output_path"]


def send_credentials_email(username: str, email: str, password: str) -> Tuple[bool, str]:
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_sender = os.getenv("SMTP_SENDER", smtp_username or "no-reply@example.com")
    smtp_use_tls = os.getenv("SMTP_USE_TLS", "true").lower() == "true"

    if not smtp_host or not smtp_username or not smtp_password:
        return False, "SMTP non configurato: credenziali create ma email non inviata."

    msg = EmailMessage()
    msg["Subject"] = f"Credenziali di accesso - {APP_TITLE}"
    msg["From"] = smtp_sender
    msg["To"] = email
    msg.set_content(
        f"""Buongiorno,\n\nsono state create le credenziali per accedere a {APP_TITLE}.\n\nUsername: {username}\nPassword: {password}\n"""
    )

    context = ssl.create_default_context()
    try:
        if smtp_use_tls:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
                server.starttls(context=context)
                server.login(smtp_username, smtp_password)
                server.send_message(msg)
        else:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context, timeout=30) as server:
                server.login(smtp_username, smtp_password)
                server.send_message(msg)
    except Exception as exc:
        return False, f"Email non inviata: {exc}"

    return True, "Email con credenziali inviata correttamente."


# ----------------------------
# Utility
# ----------------------------
def safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def remove_timezone_for_excel(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for col in df.columns:
        if pd.api.types.is_datetime64tz_dtype(df[col].dtype):
            df[col] = df[col].dt.tz_localize(None)
    return df


def normalize_pvgis_raddatabase(selected: str) -> str:
    return selected


def get_db_year_limits(raddatabase: str) -> Tuple[int, int]:
    return PVGIS_DB_YEAR_LIMITS.get(normalize_pvgis_raddatabase(raddatabase), (2005, 2023))


def tracking_to_code(tracking_mode: str) -> int:
    if tracking_mode == "trackingtype_horizontal":
        return 1
    if tracking_mode == "trackingtype_biaxial":
        return 2
    if tracking_mode == "trackingtype_tilted":
        return 5
    return 0


def pick_percentile_value(percentile: float) -> float:
    p = float(percentile)
    if p > 1:
        p = p / 100.0
    if p < 0 or p > 1:
        raise ValueError("Il percentile deve essere compreso tra 0 e 100.")
    return p


def build_run_filename(plant_code: str, source: str, percentile: int) -> str:
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_code = plant_code.replace(" ", "_")
    safe_source = source.replace(" ", "_").replace("/", "_")
    return f"{safe_code}_{safe_source}_P{percentile}_{ts}.xlsx"


# ----------------------------
# API helpers
# ----------------------------
def build_pvgis_params(cfg: Dict) -> Dict:
    params = {
        "lat": cfg["lat"],
        "lon": cfg["lon"],
        "startyear": cfg["startyear"],
        "endyear": cfg["endyear"],
        "pvcalculation": 1,
        "peakpower": cfg["peakpower"],
        "pvtechchoice": cfg["pvtechchoice"],
        "mountingplace": cfg["mountingplace"],
        "loss": cfg["loss"],
        "trackingtype": tracking_to_code(cfg["tracking_mode"]),
        "angle": cfg["angle"],
        "aspect": cfg["aspect"],
        "optimalangles": int(cfg["optimalangles"]),
        "usehorizon": int(cfg["usehorizon"]),
        "components": int(cfg["components"]),
        "raddatabase": normalize_pvgis_raddatabase(cfg["raddatabase"]),
        "outputformat": "json",
    }
    return params


def fetch_pvgis_hourly(cfg: Dict) -> pd.DataFrame:
    response = requests.get(PVGIS_BASE_URL, params=build_pvgis_params(cfg), timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    payload = response.json()
    hourly = payload.get("outputs", {}).get("hourly", [])
    if not hourly:
        raise ValueError("PVGIS non ha restituito dati orari.")

    df = pd.DataFrame(hourly)
    if "time" not in df.columns:
        raise ValueError("Colonna 'time' non trovata nella risposta PVGIS.")

    df["timestamp_utc"] = pd.to_datetime(df["time"], format="%Y%m%d:%H%M", utc=True)
    df["year"] = df["timestamp_utc"].dt.year
    df["month"] = df["timestamp_utc"].dt.month
    df["day"] = df["timestamp_utc"].dt.day
    df["hour"] = df["timestamp_utc"].dt.hour
    df["mdh_key"] = df["timestamp_utc"].dt.strftime("%m-%d %H:00")
    return df


def build_nasa_params(cfg: Dict, lat: float, lon: float) -> Dict:
    return {
        "parameters": ",".join(cfg["parameters"]),
        "community": "RE",
        "longitude": lon,
        "latitude": lat,
        "start": cfg["start_date"].strftime("%Y%m%d"),
        "end": cfg["end_date"].strftime("%Y%m%d"),
        "format": "JSON",
        "time-standard": "UTC",
    }


def fetch_nasa_hourly(cfg: Dict, lat: float, lon: float) -> pd.DataFrame:
    response = requests.get(NASA_BASE_URL, params=build_nasa_params(cfg, lat, lon), timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    payload = response.json()
    parameters = payload.get("properties", {}).get("parameter", {})
    if not parameters:
        raise ValueError("NASA POWER non ha restituito dati orari.")

    series = []
    for param_name, values in parameters.items():
        s = pd.Series(values, name=param_name)
        series.append(s)

    df = pd.concat(series, axis=1).reset_index().rename(columns={"index": "source_time_key"})
    df["timestamp_utc"] = pd.to_datetime(df["source_time_key"], format="%Y%m%d%H", utc=True)
    for c in [c for c in df.columns if c not in {"source_time_key", "timestamp_utc"}]:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df["source"] = "NASA POWER"
    return df


def build_open_meteo_params(cfg: Dict, lat: float, lon: float, tilt: float, azimuth: float) -> Dict:
    hourly_vars = cfg.get("open_meteo_hourly_variables", OPEN_METEO_RECOMMENDED_DEFAULT)
    return {
        "latitude": lat,
        "longitude": lon,
        "start_date": cfg["start_date"].isoformat(),
        "end_date": cfg["end_date"].isoformat(),
        "hourly": ",".join(hourly_vars),
        "tilt": tilt,
        "azimuth": azimuth,
        "timezone": "GMT",
        "wind_speed_unit": "ms",
        "temperature_unit": "celsius",
    }


def fetch_open_meteo_hourly(cfg: Dict, lat: float, lon: float, tilt: float, azimuth: float) -> pd.DataFrame:
    response = requests.get(OPEN_METEO_ARCHIVE_URL, params=build_open_meteo_params(cfg, lat, lon, tilt, azimuth), timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    payload = response.json()
    hourly = payload.get("hourly", {})
    if not hourly or "time" not in hourly:
        raise ValueError("Open-Meteo non ha restituito dati orari.")
    df = pd.DataFrame(hourly)
    df["timestamp_utc"] = pd.to_datetime(df["time"], utc=True)
    for c in [c for c in df.columns if c not in {"time", "timestamp_utc"}]:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df["source"] = "Open-Meteo"
    return df


# ----------------------------
# Transformations
# ----------------------------
def aggregate_pvgis_baseline(df: pd.DataFrame, percentile: float, plant_code: str) -> pd.DataFrame:
    p = pick_percentile_value(percentile)
    exclude = {"time", "timestamp_utc", "year", "month", "day", "hour", "mdh_key"}
    numeric_cols = [c for c in df.columns if c not in exclude and pd.api.types.is_numeric_dtype(df[c])]
    if not numeric_cols:
        raise ValueError("PVGIS non contiene colonne numeriche da aggregare.")

    grouped = df.groupby(["month", "day", "hour"], dropna=False)
    agg = grouped[numeric_cols].quantile(p).reset_index()

    # PVGIS restituisce P in W. Per confronto orario coerente con kWh/misurato,
    # usiamo anche una colonna energetica equivalente su base oraria.
    if "P" in agg.columns:
        agg["baseline_power_w"] = pd.to_numeric(agg["P"], errors="coerce")
        agg["baseline_energy_kwh"] = agg["baseline_power_w"] / 1000.0

    agg["baseline_timestamp_utc"] = pd.to_datetime(
        {"year": 2020, "month": agg["month"], "day": agg["day"], "hour": agg["hour"]},
        utc=True,
        errors="coerce",
    )
    agg = agg.dropna(subset=["baseline_timestamp_utc"]).sort_values("baseline_timestamp_utc").reset_index(drop=True)
    agg["mdh_key"] = agg["baseline_timestamp_utc"].dt.strftime("%m-%d %H:00")
    agg.insert(0, "codice_impianto", plant_code)
    agg.insert(1, "baseline_percentile", p)
    return agg


def add_common_time_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["month"] = df["timestamp_utc"].dt.month
    df["day"] = df["timestamp_utc"].dt.day
    df["hour"] = df["timestamp_utc"].dt.hour
    df["mdh_key"] = df["timestamp_utc"].dt.strftime("%m-%d %H:00")
    return df


def compute_expected_from_recent_weather(df: pd.DataFrame, plant_cfg: Dict, source_name: str) -> pd.DataFrame:
    out = df.copy()
    out = add_common_time_columns(out)

    if source_name == "Open-Meteo":
        out["irradiance_proxy_wm2"] = out.get("global_tilted_irradiance", pd.Series(index=out.index, dtype=float))
        out["ghi_wm2"] = out.get("shortwave_radiation", pd.Series(index=out.index, dtype=float))
        out["dni_wm2"] = out.get("direct_normal_irradiance", pd.Series(index=out.index, dtype=float))
        out["dhi_wm2"] = out.get("diffuse_radiation", pd.Series(index=out.index, dtype=float))
        out["temp_air_c"] = out.get("temperature_2m", pd.Series(index=out.index, dtype=float))
        out["wind_10m_ms"] = out.get("wind_speed_10m", pd.Series(index=out.index, dtype=float))
        irradiance_basis = "GTI"
    else:
        out["ghi_wm2"] = out.get("ALLSKY_SFC_SW_DWN", pd.Series(index=out.index, dtype=float))
        out["dni_wm2"] = out.get("ALLSKY_SFC_SW_DNI", pd.Series(index=out.index, dtype=float))
        out["dhi_wm2"] = out.get("ALLSKY_SFC_SW_DIFF", pd.Series(index=out.index, dtype=float))
        out["temp_air_c"] = out.get("T2M", pd.Series(index=out.index, dtype=float))
        out["wind_10m_ms"] = out.get("WS10M", pd.Series(index=out.index, dtype=float))
        out["irradiance_proxy_wm2"] = out["ghi_wm2"]
        irradiance_basis = "GHI proxy"

    out["irradiance_proxy_wm2"] = pd.to_numeric(out["irradiance_proxy_wm2"], errors="coerce").clip(lower=0)
    out["temp_air_c"] = pd.to_numeric(out["temp_air_c"], errors="coerce")
    out["wind_10m_ms"] = pd.to_numeric(out["wind_10m_ms"], errors="coerce")

    gamma = TECH_TEMP_COEFF.get(plant_cfg["pvtechchoice"], -0.0040)
    noct_c = 45.0
    out["temp_cell_c"] = out["temp_air_c"].fillna(25.0) + ((noct_c - 20.0) / 800.0) * out["irradiance_proxy_wm2"].fillna(0.0)
    out["temp_factor"] = 1.0 + gamma * (out["temp_cell_c"] - 25.0)
    out["temp_factor"] = out["temp_factor"].clip(lower=0.0)
    out["loss_factor"] = max(0.0, 1.0 - (safe_float(plant_cfg["loss"], 0.0) / 100.0))

    out["expected_energy_kwh"] = (
        safe_float(plant_cfg["peakpower"], 0.0)
        * (out["irradiance_proxy_wm2"] / 1000.0)
        * out["temp_factor"]
        * out["loss_factor"]
    )
    out["expected_power_kw_proxy"] = out["expected_energy_kwh"]
    out["expected_method"] = f"{source_name} - {irradiance_basis}"
    return out


def load_monitoring_file(uploaded_file) -> pd.DataFrame:
    name = uploaded_file.name.lower()
    if name.endswith(".csv"):
        df = pd.read_csv(uploaded_file)
    elif name.endswith(".xlsx") or name.endswith(".xls"):
        df = pd.read_excel(uploaded_file)
    else:
        raise ValueError("Formato file monitoraggio non supportato. Usa CSV o Excel.")
    if df.empty:
        raise ValueError("Il file di monitoraggio è vuoto.")
    return df


def prepare_monitoring_df(raw_df: pd.DataFrame, ts_col: str, prod_col: str, peakpower_kwp: float) -> pd.DataFrame:
    df = raw_df.copy()
    df["timestamp_utc"] = pd.to_datetime(df[ts_col], utc=True, errors="coerce")
    df["measured_energy_kwh"] = pd.to_numeric(df[prod_col], errors="coerce")
    df = df.dropna(subset=["timestamp_utc"]).copy()
    df = add_common_time_columns(df)
    df = df[["timestamp_utc", "month", "day", "hour", "mdh_key", "measured_energy_kwh"]].dropna(subset=["measured_energy_kwh"])

    if df.empty:
        raise ValueError("La colonna selezionata per la produzione misurata non contiene valori numerici validi.")

    median_val = float(pd.to_numeric(df["measured_energy_kwh"], errors="coerce").median())
    max_val = float(pd.to_numeric(df["measured_energy_kwh"], errors="coerce").max())
    plausible_hourly_limit = max(10.0, float(peakpower_kwp) * 3.0)

    if median_val > plausible_hourly_limit or max_val > plausible_hourly_limit * 10:
        raise ValueError(
            "La colonna selezionata come produzione misurata non sembra essere espressa in kWh orari. "
            "Probabilmente hai scelto una colonna timestamp o un identificativo numerico."
        )

    return df


def compare_expected_vs_measured(expected_df: pd.DataFrame, monitoring_df: Optional[pd.DataFrame], baseline_df: pd.DataFrame) -> pd.DataFrame:
    baseline_cols = ["mdh_key"]
    for c in ["baseline_energy_kwh", "baseline_power_w", "G(i)", "Gb(i)", "Gd(i)", "Gr(i)", "H_sun", "T2m", "WS10m"]:
        if c in baseline_df.columns:
            baseline_cols.append(c)

    baseline_small = baseline_df[baseline_cols].copy()
    rename_map = {
        "G(i)": "baseline_Gi_wm2",
        "Gb(i)": "baseline_Gb_i_wm2",
        "Gd(i)": "baseline_Gd_i_wm2",
        "Gr(i)": "baseline_Gr_i_wm2",
        "H_sun": "baseline_H_sun_deg",
        "T2m": "baseline_T2m_c",
        "WS10m": "baseline_WS10m_ms",
    }
    baseline_small = baseline_small.rename(columns=rename_map)

    out = expected_df.merge(baseline_small, on="mdh_key", how="left")

    if monitoring_df is not None and not monitoring_df.empty:
        out = out.merge(monitoring_df, on="timestamp_utc", how="left")
        out["deviation_kwh"] = out["measured_energy_kwh"] - out["expected_energy_kwh"]
        denom = out["expected_energy_kwh"].replace(0, pd.NA)
        out["deviation_pct"] = (out["deviation_kwh"] / denom) * 100.0
        out["performance_ratio_proxy"] = out["measured_energy_kwh"] / denom
    else:
        out["measured_energy_kwh"] = pd.NA
        out["deviation_kwh"] = pd.NA
        out["deviation_pct"] = pd.NA
        out["performance_ratio_proxy"] = pd.NA

    return out


def summarize_kpis(comparison_df: pd.DataFrame, source_name: str, percentile: int) -> pd.DataFrame:
    summary = {
        "source_meteo": source_name,
        "baseline_percentile": percentile,
        "rows_comparison": int(len(comparison_df)),
        "expected_energy_total_kwh": pd.to_numeric(comparison_df["expected_energy_kwh"], errors="coerce").sum(),
        "measured_energy_total_kwh": pd.to_numeric(comparison_df["measured_energy_kwh"], errors="coerce").sum(),
        "mean_deviation_pct": pd.to_numeric(comparison_df["deviation_pct"], errors="coerce").mean(),
        "median_deviation_pct": pd.to_numeric(comparison_df["deviation_pct"], errors="coerce").median(),
        "mean_performance_ratio_proxy": pd.to_numeric(comparison_df["performance_ratio_proxy"], errors="coerce").mean(),
        "hours_with_measurements": int(pd.to_numeric(comparison_df["measured_energy_kwh"], errors="coerce").notna().sum()),
        "hours_large_negative_deviation_lt_minus_15pct": int((pd.to_numeric(comparison_df["deviation_pct"], errors="coerce") < -15).sum()),
    }
    return pd.DataFrame([summary])


def to_excel_bytes(
    config_rows: List[Dict],
    baseline_raw: pd.DataFrame,
    baseline_percentile: pd.DataFrame,
    recent_weather_raw: pd.DataFrame,
    expected_recent: pd.DataFrame,
    comparison_df: pd.DataFrame,
    monitoring_raw: Optional[pd.DataFrame],
    kpi_df: pd.DataFrame,
) -> bytes:
    buffer = BytesIO()
    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        pd.DataFrame(config_rows).to_excel(writer, sheet_name="INPUT_CONFIG", index=False)
        remove_timezone_for_excel(baseline_raw).to_excel(writer, sheet_name="PVGIS_BASELINE_RAW", index=False)
        remove_timezone_for_excel(baseline_percentile).to_excel(writer, sheet_name="PVGIS_BASELINE_PCTL", index=False)
        remove_timezone_for_excel(recent_weather_raw).to_excel(writer, sheet_name="RECENT_WEATHER_RAW", index=False)
        remove_timezone_for_excel(expected_recent).to_excel(writer, sheet_name="EXPECTED_RECENT", index=False)
        remove_timezone_for_excel(comparison_df).to_excel(writer, sheet_name="COMPARISON", index=False)
        if monitoring_raw is not None:
            remove_timezone_for_excel(monitoring_raw).to_excel(writer, sheet_name="MONITORING_RAW", index=False)
        kpi_df.to_excel(writer, sheet_name="KPI_SUMMARY", index=False)

        workbook = writer.book
        for ws in workbook.worksheets:
            ws.freeze_panes = "A2"
            for column_cells in ws.columns:
                length = max(len(str(cell.value)) if cell.value is not None else 0 for cell in column_cells)
                ws.column_dimensions[column_cells[0].column_letter].width = min(max(length + 2, 12), 40)
    buffer.seek(0)
    return buffer.getvalue()


# ----------------------------
# UI
# ----------------------------
def login_ui() -> None:
    st.title(APP_TITLE)
    st.subheader("Accesso")
    with st.form("login_form"):
        username = st.text_input("Account")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Accedi")

    if submitted:
        user = authenticate(username.strip(), password)
        if user:
            st.session_state["user"] = user
            st.rerun()
        else:
            st.error("Credenziali non valide.")


def admin_ui(current_user: Dict) -> None:
    st.markdown("### Amministrazione utenti")
    users_df = list_users()

    tab1, tab2, tab3 = st.tabs(["Crea", "Modifica", "Cancella"])

    with tab1:
        with st.form("create_user_form"):
            c1, c2 = st.columns(2)
            with c1:
                new_username = st.text_input("Nuovo account")
                new_email = st.text_input("Email")
            with c2:
                new_password = st.text_input("Password iniziale", type="password")
                new_is_admin = st.checkbox("Utente amministratore")
            create_submitted = st.form_submit_button("Crea utente")
        if create_submitted:
            try:
                create_user(new_username.strip(), new_email.strip(), new_password, new_is_admin)
                ok, message = send_credentials_email(new_username.strip(), new_email.strip(), new_password)
                st.success("Utente creato.")
                if ok:
                    st.success(message)
                else:
                    st.warning(message)
                st.rerun()
            except sqlite3.IntegrityError:
                st.error("Username già presente.")
            except Exception as exc:
                st.error(f"Errore nella creazione utente: {exc}")

    with tab2:
        if users_df.empty:
            st.info("Nessun utente disponibile.")
        else:
            usernames = users_df["username"].tolist()
            selected_username = st.selectbox("Seleziona utente da modificare", usernames, key="edit_user")
            row = users_df.loc[users_df["username"] == selected_username].iloc[0]
            with st.form("edit_user_form"):
                e1, e2 = st.columns(2)
                with e1:
                    edit_username = st.text_input("Account", value=row["username"])
                    edit_email = st.text_input("Email", value=row["email"])
                with e2:
                    edit_is_admin = st.checkbox("Utente amministratore", value=bool(row["is_admin"]))
                    edit_password = st.text_input("Nuova password (lascia vuoto per non cambiarla)", type="password")
                edit_submitted = st.form_submit_button("Salva modifiche")
            if edit_submitted:
                try:
                    update_user(int(row["id"]), edit_username.strip(), edit_email.strip(), edit_is_admin, edit_password)
                    st.success("Utente aggiornato.")
                    st.rerun()
                except Exception as exc:
                    st.error(f"Errore aggiornamento utente: {exc}")

    with tab3:
        if users_df.empty:
            st.info("Nessun utente disponibile.")
        else:
            usernames = users_df["username"].tolist()
            selected_delete = st.selectbox("Seleziona utente da cancellare", usernames, key="delete_user")
            row_del = users_df.loc[users_df["username"] == selected_delete].iloc[0]
            if st.button("Cancella utente selezionato"):
                try:
                    delete_user(int(row_del["id"]), int(current_user["id"]))
                    st.success("Utente cancellato.")
                    st.rerun()
                except Exception as exc:
                    st.error(f"Errore cancellazione utente: {exc}")

    st.dataframe(users_df, use_container_width=True)


def render_runs_ui(current_user: Dict) -> None:
    st.markdown("### Storico elaborazioni")
    runs_df = list_runs(None if int(current_user["is_admin"]) == 1 else current_user["username"])
    if runs_df.empty:
        st.info("Nessuna elaborazione salvata.")
        return

    st.dataframe(runs_df, use_container_width=True)
    selected_run_id = st.selectbox("Seleziona run da scaricare", runs_df["id"].tolist(), format_func=lambda x: f"Run {x}")
    selected_row = runs_df.loc[runs_df["id"] == selected_run_id].iloc[0]
    path = get_run_file_path(int(selected_run_id))
    if path and os.path.exists(path):
        with open(path, "rb") as f:
            st.download_button(
                "Scarica Excel del run selezionato",
                data=f.read(),
                file_name=str(selected_row["output_filename"]),
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                key=f"download_run_{selected_run_id}",
            )
    else:
        st.warning("File del run non trovato sul server.")


def validation_checks(plant_cfg: Dict, baseline_cfg: Dict, recent_cfg: Dict, source_name: str, monitoring_present: bool) -> None:
    min_year, max_year = get_db_year_limits(plant_cfg["raddatabase"])
    if baseline_cfg["startyear"] < min_year or baseline_cfg["endyear"] > max_year:
        raise ValueError(f"Con {plant_cfg['raddatabase']} gli anni disponibili sono {min_year}-{max_year}.")
    if baseline_cfg["startyear"] > baseline_cfg["endyear"]:
        raise ValueError("L'anno iniziale PVGIS non può essere maggiore dell'anno finale.")
    if recent_cfg["start_date"] > recent_cfg["end_date"]:
        raise ValueError("La data iniziale del meteo recente non può essere successiva alla data finale.")
    if not (-90 <= plant_cfg["lat"] <= 90):
        raise ValueError("Latitudine non valida.")
    if not (-180 <= plant_cfg["lon"] <= 180):
        raise ValueError("Longitudine non valida.")
    if source_name == "NASA POWER" and not recent_cfg["nasa_parameters"]:
        raise ValueError("Seleziona almeno un parametro NASA POWER.")
    if source_name == "Open-Meteo":
        selected = recent_cfg.get("open_meteo_hourly_variables", [])
        for required_var in OPEN_METEO_MIN_REQUIRED:
            if required_var not in selected:
                raise ValueError(f"Per Open-Meteo seleziona almeno i parametri obbligatori: {', '.join(OPEN_METEO_MIN_REQUIRED)}.")
    if source_name == "PVGIS recente":
        raise ValueError("PVGIS non è adatto ai dati recenti oltre il 2023 in questa app. Usa Open-Meteo o NASA POWER.")
    if not monitoring_present:
        st.warning("Nessun file di monitoraggio caricato: l'output conterrà baseline e produzione attesa recente, ma non il confronto col misurato.")


def render_structure() -> None:
    st.markdown(
        """
### Struttura funzionale
**1. Baseline storica PVGIS** → profilo storico multi-anno e percentile P50/P10  
**2. Meteo reale recente** → Open-Meteo o NASA POWER per il periodo da verificare  
**3. Monitoraggio impianto** → file CSV/Excel con timestamp e produzione misurata  
**4. Produzione attesa corretta** → stima oraria da irraggiamento recente + temperatura + perdite  
**5. Verifica** → confronto tra atteso, misurato e baseline storica
        """
    )


def app_ui() -> None:
    st.title(APP_TITLE)
    user = st.session_state["user"]
    st.caption(f"Connesso come: {user['username']}")

    c1, c2 = st.columns([1, 5])
    with c1:
        if st.button("Logout"):
            st.session_state.clear()
            st.rerun()
    with c2:
        st.write("")

    render_structure()

    if int(user["is_admin"]) == 1:
        with st.expander("Amministrazione", expanded=False):
            admin_ui(user)

    with st.expander("Run elaborazioni", expanded=False):
        render_runs_ui(user)

    today_minus_7 = date.today() - timedelta(days=7)
    default_recent_start = today_minus_7 - timedelta(days=2)

    with st.form("verification_form"):
        st.markdown("### A. Configurazione impianto")
        a1, a2, a3 = st.columns(3)
        with a1:
            codice_impianto = st.text_input("Codice impianto", value="SRB_xxx")
            lat = st.number_input("Latitudine", value=41.8927524, format="%.7f")
            lon = st.number_input("Longitudine", value=12.4853054, format="%.7f")
            peakpower = st.number_input("Peak power [kWp]", min_value=0.0, value=1.0, step=0.1)
            loss = st.number_input("Loss [%]", min_value=0.0, max_value=100.0, value=14.0, step=0.5)
        with a2:
            pvtechchoice = st.selectbox("Tecnologia pannello", ["crystSi", "CIS", "CdTe", "Unknown"], index=0)
            mountingplace = st.selectbox("Tipo di montaggio", ["free", "building"], index=0)
            optimalangles = st.checkbox("Optimal angles", value=False)
            angle = st.number_input("Tilt [°]", min_value=0.0, max_value=90.0, value=30.0, step=1.0)
            aspect = st.number_input("Azimut [°]", min_value=-180.0, max_value=180.0, value=0.0, step=1.0)
        with a3:
            tracking_mode = st.selectbox(
                "Tracking",
                ["fixed", "trackingtype_horizontal", "trackingtype_tilted", "trackingtype_biaxial"],
                index=0,
            )
            raddatabase = st.selectbox("Radiation database PVGIS", ["PVGIS-SARAH3", "PVGIS-ERA5", "PVGIS-SARAH2"], index=0)
            min_year, max_year = get_db_year_limits(raddatabase)
            startyear = st.number_input("Anno iniziale baseline", min_value=min_year, max_value=max_year, value=min_year, step=1)
            endyear = st.number_input("Anno finale baseline", min_value=min_year, max_value=max_year, value=max_year, step=1)
            usehorizon = st.checkbox("Use horizon", value=True)
            components = st.checkbox("Radiation components", value=True)

        st.markdown("### B. Baseline storica")
        percentile = st.selectbox("Percentile baseline", [10, 50], index=1)

        st.markdown("### C. Meteo reale recente")
        source_name = st.selectbox("Fonte meteo recente", ["Open-Meteo", "NASA POWER"], index=0, key="weather_source")
        r1, r2 = st.columns(2)
        with r1:
            recent_start_date = st.date_input("Data iniziale meteo recente", value=default_recent_start)
        with r2:
            recent_end_date = st.date_input("Data finale meteo recente", value=today_minus_7)

        st.caption(
            f"I parametri geometrici e temporali della richiesta vengono ereditati dalla configurazione già compilata: "
            f"lat={lat}, lon={lon}, periodo={recent_start_date} → {recent_end_date}, tilt={angle}°, azimut={aspect}°."
        )

        if source_name == "Open-Meteo":
            st.markdown("#### Configurazione Open-Meteo")
            st.info(
                "Open-Meteo usa automaticamente coordinate, periodo, tilt e azimut già inseriti sopra. "
                "Qui devi scegliere solo le misure orarie da scaricare."
            )
            st.write("**Parametri usati automaticamente**")
            st.json({
                "latitude": float(lat),
                "longitude": float(lon),
                "start_date": str(recent_start_date),
                "end_date": str(recent_end_date),
                "timezone": "GMT",
                "tilt": float(angle),
                "azimuth": float(aspect),
            })

            open_meteo_hourly_variables = st.multiselect(
                "Misure orarie da scaricare (Open-Meteo)",
                options=list(OPEN_METEO_VARIABLE_LABELS.keys()),
                default=OPEN_METEO_RECOMMENDED_DEFAULT,
                format_func=lambda x: f"{x} — {OPEN_METEO_VARIABLE_LABELS.get(x, x)}",
                key="open_meteo_vars",
                help="Per il calcolo produzione tieni almeno global_tilted_irradiance e temperature_2m.",
            )
            nasa_parameters = []
        else:
            st.markdown("#### Configurazione NASA POWER")
            st.info(
                "NASA POWER usa automaticamente coordinate e periodo già inseriti sopra. "
                "L'orario viene richiesto in UTC. Qui devi scegliere solo le misure orarie da scaricare."
            )
            st.write("**Parametri usati automaticamente**")
            st.json({
                "latitude": float(lat),
                "longitude": float(lon),
                "start": recent_start_date.strftime("%Y%m%d"),
                "end": recent_end_date.strftime("%Y%m%d"),
                "community": "RE",
                "format": "JSON",
                "time-standard": "UTC",
            })

            nasa_parameters = st.multiselect(
                "Misure orarie da scaricare (NASA POWER)",
                options=list(NASA_PARAMETER_LABELS.keys()),
                default=["ALLSKY_SFC_SW_DWN", "T2M", "WS10M", "ALLSKY_SFC_SW_DNI", "ALLSKY_SFC_SW_DIFF"],
                format_func=lambda x: f"{x} — {NASA_PARAMETER_LABELS.get(x, x)}",
                key="nasa_power_vars",
                help="Per il calcolo produzione tieni almeno ALLSKY_SFC_SW_DWN e T2M.",
            )
            open_meteo_hourly_variables = []

        st.markdown("### D. Dati di monitoraggio")
        monitoring_file = st.file_uploader("Carica CSV o Excel del monitoraggio", type=["csv", "xlsx", "xls"])

        submit = st.form_submit_button("Esegui verifica e genera output")

    if not submit:
        return

    try:
        plant_cfg = {
            "codice_impianto": codice_impianto,
            "lat": float(lat),
            "lon": float(lon),
            "peakpower": float(peakpower),
            "loss": float(loss),
            "pvtechchoice": pvtechchoice,
            "mountingplace": mountingplace,
            "optimalangles": bool(optimalangles),
            "angle": float(angle),
            "aspect": float(aspect),
            "tracking_mode": tracking_mode,
            "raddatabase": raddatabase,
            "usehorizon": bool(usehorizon),
            "components": bool(components),
        }
        baseline_cfg = {"startyear": int(startyear), "endyear": int(endyear), "percentile": int(percentile)}
        recent_cfg = {
            "start_date": recent_start_date,
            "end_date": recent_end_date,
            "nasa_parameters": nasa_parameters,
            "open_meteo_hourly_variables": open_meteo_hourly_variables,
        }

        validation_checks(plant_cfg, baseline_cfg, recent_cfg, source_name, monitoring_file is not None)

        progress = st.progress(0, text="Validazione input completata")
        status = st.empty()

        status.info("1/5 - Scarico baseline PVGIS")
        pvgis_cfg = dict(plant_cfg)
        pvgis_cfg.update({"startyear": baseline_cfg["startyear"], "endyear": baseline_cfg["endyear"]})
        baseline_raw = fetch_pvgis_hourly(pvgis_cfg)
        baseline_percentile = aggregate_pvgis_baseline(baseline_raw, percentile=baseline_cfg["percentile"], plant_code=plant_cfg["codice_impianto"])
        progress.progress(20, text="Baseline PVGIS pronta")

        status.info(f"2/5 - Scarico meteo recente da {source_name}")
        if source_name == "Open-Meteo":
            recent_weather_raw = fetch_open_meteo_hourly(recent_cfg, plant_cfg["lat"], plant_cfg["lon"], plant_cfg["angle"], plant_cfg["aspect"])
        else:
            nasa_cfg = {
                "parameters": recent_cfg["nasa_parameters"],
                "start_date": recent_cfg["start_date"],
                "end_date": recent_cfg["end_date"],
            }
            recent_weather_raw = fetch_nasa_hourly(nasa_cfg, plant_cfg["lat"], plant_cfg["lon"])
        progress.progress(45, text="Meteo recente scaricato")

        status.info("3/5 - Calcolo produzione attesa recente")
        expected_recent = compute_expected_from_recent_weather(recent_weather_raw, plant_cfg, source_name)
        progress.progress(65, text="Produzione attesa calcolata")

        monitoring_raw = None
        monitoring_prepared = None
        if monitoring_file is not None:
            status.info("4/5 - Carico il file di monitoraggio e chiedo il mapping colonne")
            monitoring_raw = load_monitoring_file(monitoring_file)
            st.subheader("Mapping colonne monitoraggio")
            candidate_ts_cols = monitoring_raw.columns.tolist()
            candidate_prod_cols = [
                c for c in monitoring_raw.columns
                if pd.api.types.is_numeric_dtype(monitoring_raw[c])
                or any(token in c.lower() for token in ["energy", "energia", "kwh", "power", "potenza", "prod"])
            ]
            if not candidate_prod_cols:
                candidate_prod_cols = monitoring_raw.columns.tolist()

            default_ts_idx = candidate_ts_cols.index("timestamp_utc") if "timestamp_utc" in candidate_ts_cols else 0
            default_prod_idx = candidate_prod_cols.index("measured_energy_kwh") if "measured_energy_kwh" in candidate_prod_cols else 0

            m1, m2 = st.columns(2)
            with m1:
                ts_col = st.selectbox("Colonna timestamp", candidate_ts_cols, index=default_ts_idx, key="ts_col")
            with m2:
                prod_col = st.selectbox("Colonna energia/prodotto [kWh]", candidate_prod_cols, index=default_prod_idx, key="prod_col")
            monitoring_prepared = prepare_monitoring_df(monitoring_raw, ts_col, prod_col, peakpower_kwp=plant_cfg["peakpower"])
        progress.progress(82, text="Monitoraggio preparato")

        status.info("5/5 - Costruisco confronto, KPI ed Excel")
        comparison_df = compare_expected_vs_measured(expected_recent, monitoring_prepared, baseline_percentile)
        kpi_df = summarize_kpis(comparison_df, source_name, int(percentile))

        config_rows = [
            {"section": "plant", "key": k, "value": v} for k, v in plant_cfg.items()
        ] + [
            {"section": "baseline", "key": k, "value": v} for k, v in baseline_cfg.items()
        ] + [
            {"section": "recent_weather", "key": k, "value": v.isoformat() if hasattr(v, "isoformat") else v} for k, v in recent_cfg.items()
        ] + [
            {"section": "run", "key": "generated_at_utc", "value": datetime.utcnow().isoformat()},
            {"section": "run", "key": "user", "value": user["username"]},
            {"section": "run", "key": "weather_source", "value": source_name},
        ]

        output_name = build_run_filename(codice_impianto, source_name, int(percentile))
        excel_bytes = to_excel_bytes(
            config_rows=config_rows,
            baseline_raw=baseline_raw,
            baseline_percentile=baseline_percentile,
            recent_weather_raw=recent_weather_raw,
            expected_recent=expected_recent,
            comparison_df=comparison_df,
            monitoring_raw=monitoring_raw,
            kpi_df=kpi_df,
        )

        progress.progress(100, text="Elaborazione completata")
        status.success("Output pronto")

        st.subheader("KPI sintetici")
        st.dataframe(kpi_df, use_container_width=True)

        st.subheader("Prime righe del confronto")
        view_cols = [
            c for c in [
                "timestamp_utc", "expected_energy_kwh", "measured_energy_kwh", "deviation_pct",
                "performance_ratio_proxy", "irradiance_proxy_wm2", "temp_air_c", "expected_method",
                "baseline_energy_kwh", "baseline_power_w", "baseline_Gi_wm2"
            ] if c in comparison_df.columns
        ]
        st.dataframe(comparison_df[view_cols].head(100), use_container_width=True)

        st.subheader("Grafico orario di confronto")
        chart_df = comparison_df.copy().sort_values("timestamp_utc")
        chart_cols = [c for c in ["expected_energy_kwh", "measured_energy_kwh", "baseline_energy_kwh"] if c in chart_df.columns]
        if chart_cols:
            line_df = chart_df[["timestamp_utc"] + chart_cols].set_index("timestamp_utc")
            st.line_chart(line_df, height=360)
        else:
            st.info("Non ci sono abbastanza dati per il grafico orario.")

        saved_path = save_run_record(
            username=user["username"],
            plant_code=codice_impianto,
            weather_source=source_name,
            percentile=int(percentile),
            output_filename=output_name,
            output_bytes=excel_bytes,
            kpi_df=kpi_df,
        )
        st.caption(f"Run salvato: {saved_path}")

        st.download_button(
            "Scarica Excel di output",
            data=excel_bytes,
            file_name=output_name,
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

        with st.expander("Note metodologiche"):
            st.write(
                "Open-Meteo usa GTI oraria se disponibile; NASA POWER usa GHI come proxy semplice dell'irraggiamento sul piano. "
                "La baseline PVGIS viene convertita da P [W] a baseline_energy_kwh su base oraria dividendo per 1000. "
                "La produzione attesa recente viene calcolata moltiplicando esplicitamente per la peak power dell'impianto [kWp]."
            )
    except requests.HTTPError as exc:
        body = exc.response.text[:1200] if exc.response is not None else str(exc)
        st.error(f"Errore HTTP dalle API: {body}")
    except Exception as exc:
        st.error(f"Errore: {exc}")


def main() -> None:
    st.set_page_config(page_title=APP_TITLE, layout="wide")
    init_db()
    if "user" not in st.session_state:
        login_ui()
    else:
        app_ui()


if __name__ == "__main__":
    main()
