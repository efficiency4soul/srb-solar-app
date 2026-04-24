
import os
import sqlite3
import smtplib
import ssl
import secrets
import hashlib
import re
from datetime import date, datetime, timedelta
from email.message import EmailMessage
from io import BytesIO
from typing import Dict, List, Optional, Tuple

import pandas as pd
import requests
import streamlit as st

APP_TITLE = "Tower PV Analytics"
APP_SUBTITLE = "Solar Performance Intelligence for Telecom Towers"
DB_PATH = "users.db"
RUNS_DIR = "runs"
REQUEST_TIMEOUT = 90
DEFAULT_OUTPUT_NAME = "TowerPVAnalytics_output.xlsx"
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


def save_run_record(
    username: str,
    plant_code: str,
    weather_source: str,
    percentile: int,
    output_filename: str,
    output_bytes: bytes,
    kpi_df: pd.DataFrame,
) -> str:
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
        if pd.isna(value):
            return default
        return float(value)
    except Exception:
        return default


def safe_int(value, default=0):
    try:
        if pd.isna(value):
            return default
        return int(float(value))
    except Exception:
        return default


def parse_bool(value, default=False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return default
    s = str(value).strip().lower()
    true_values = {"1", "true", "vero", "yes", "si", "sì", "y", "x"}
    false_values = {"0", "false", "falso", "no", "n", ""}
    if s in true_values:
        return True
    if s in false_values:
        return False
    return default


def normalize_text(s: str) -> str:
    s = "" if s is None else str(s)
    s = s.strip().lower()
    s = s.replace("à", "a").replace("è", "e").replace("é", "e").replace("ì", "i").replace("ò", "o").replace("ù", "u")
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s


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
    return f"TowerPVAnalytics_{safe_code}_{safe_source}_P{percentile}_{ts}.xlsx"


# ----------------------------
# Plant workbook parsing
# ----------------------------
CONFIG_ALIASES = {
    "codice_impianto": ["codice_impianto", "impianto", "plant_code", "codice", "site_code", "nome_impianto"],
    "lat": ["lat", "latitude", "latitudine"],
    "lon": ["lon", "lng", "longitude", "longitudine"],
    "peakpower": ["peakpower", "peak_power", "kwp", "potenza_picco_kwp", "potenza_picco", "potenza_nominale_kwp"],
    "loss": ["loss", "loss_percent", "perdite", "perdite_percento", "losses"],
    "pvtechchoice": ["pvtechchoice", "pv_tech", "tecnologia_pannello", "tecnologia", "module_technology"],
    "mountingplace": ["mountingplace", "montaggio", "tipo_montaggio", "installation_type"],
    "optimalangles": ["optimalangles", "optimal_angles", "angoli_ottimali"],
    "angle": ["angle", "tilt", "inclinazione", "tilt_deg"],
    "aspect": ["aspect", "azimuth", "azimut", "azimuth_deg"],
    "tracking_mode": ["tracking_mode", "tracking", "inseguimento"],
    "raddatabase": ["raddatabase", "rad_database", "radiation_database", "database_radiazione"],
    "startyear": ["startyear", "start_year", "anno_iniziale", "baseline_start_year"],
    "endyear": ["endyear", "end_year", "anno_finale", "baseline_end_year"],
    "usehorizon": ["usehorizon", "use_horizon", "orizzonte"],
    "components": ["components", "radiation_components", "componenti_rad"],
}

MEASURE_ALIASES = {
    "year": ["anno", "year"],
    "month": ["mese", "month"],
    "day": ["giorno", "day"],
    "hour": ["ora", "hour"],
    "power_kw": [
        "potenza_misurata_kw",
        "potenza misurata kw",
        "potenza_misurata",
        "potenza misurata",
        "potenza_kw",
        "power_kw",
        "power",
        "kw",
        "potenza",
    ],
}


def find_header_row(
    xls: pd.ExcelFile,
    sheet_name: str,
    aliases_dict: Dict[str, List[str]],
    min_found: int = 4,
    max_rows: int = 50,
) -> Optional[int]:
    """Trova la riga di intestazione anche se sopra ci sono titoli, note o righe vuote."""
    preview = pd.read_excel(
        xls,
        sheet_name=sheet_name,
        header=None,
        nrows=max_rows,
    )

    alias_groups = list(aliases_dict.values())

    for row_idx in range(len(preview)):
        row_values = [
            normalize_text(v)
            for v in preview.iloc[row_idx].tolist()
            if not pd.isna(v)
        ]

        found = 0
        for aliases in alias_groups:
            aliases_norm = [normalize_text(a) for a in aliases]
            if any(alias in row_values for alias in aliases_norm):
                found += 1

        if found >= min_found:
            return row_idx

    return None


def read_excel_with_detected_header(
    xls: pd.ExcelFile,
    sheet_name: str,
    aliases_dict: Dict[str, List[str]],
    min_found: int = 4,
) -> pd.DataFrame:
    header_row = find_header_row(
        xls=xls,
        sheet_name=sheet_name,
        aliases_dict=aliases_dict,
        min_found=min_found,
    )

    if header_row is None:
        df = pd.read_excel(xls, sheet_name=sheet_name)
    else:
        df = pd.read_excel(xls, sheet_name=sheet_name, header=header_row)

    df = df.dropna(how="all").copy()
    df.columns = [str(c).strip() for c in df.columns]
    return df


def detect_sheet_roles(xls: pd.ExcelFile) -> Tuple[Optional[str], Optional[str]]:
    config_sheet = None
    measure_sheet = None

    for sheet in xls.sheet_names:
        sheet_name_norm = normalize_text(sheet)

        # Cerca le intestazioni delle misure dentro le prime righe, non solo nella prima riga del foglio.
        measure_header_row = find_header_row(
            xls=xls,
            sheet_name=sheet,
            aliases_dict=MEASURE_ALIASES,
            min_found=4,
        )

        if measure_header_row is not None and measure_sheet is None:
            measure_sheet = sheet

        if config_sheet is None:
            if any(token in sheet_name_norm for token in ["config", "impianto", "plant", "setup", "anagrafica"]):
                config_sheet = sheet

    if config_sheet is None:
        for sheet in xls.sheet_names:
            if sheet != measure_sheet:
                config_sheet = sheet
                break

    return config_sheet, measure_sheet

def dataframe_to_key_value(df: pd.DataFrame) -> Dict[str, object]:
    out = {}

    # caso 1: prime due colonne key/value
    if df.shape[1] >= 2:
        c0 = df.columns[0]
        c1 = df.columns[1]
        for _, row in df[[c0, c1]].dropna(how="all").iterrows():
            key = normalize_text(row[c0])
            if key:
                out[key] = row[c1]

    # caso 2: una riga con intestazioni = chiavi
    if df.shape[0] >= 1:
        first_row = df.iloc[0].to_dict()
        for k, v in first_row.items():
            nk = normalize_text(k)
            if nk and nk not in out and not pd.isna(v):
                out[nk] = v

    return out


def pick_value_from_aliases(data: Dict[str, object], aliases: List[str]):
    for alias in aliases:
        n = normalize_text(alias)
        if n in data:
            return data[n]
    return None


def parse_plant_config_sheet(df: pd.DataFrame) -> Dict:
    raw_kv = dataframe_to_key_value(df)

    cfg = {}
    for target_key, aliases in CONFIG_ALIASES.items():
        cfg[target_key] = pick_value_from_aliases(raw_kv, aliases)

    # default robusti
    cfg["codice_impianto"] = cfg["codice_impianto"] or "SRB_xxx"
    cfg["lat"] = safe_float(cfg["lat"], None)
    cfg["lon"] = safe_float(cfg["lon"], None)
    cfg["peakpower"] = safe_float(cfg["peakpower"], 1.0)
    cfg["loss"] = safe_float(cfg["loss"], 14.0)
    cfg["pvtechchoice"] = str(cfg["pvtechchoice"]).strip() if cfg["pvtechchoice"] is not None else "crystSi"
    cfg["mountingplace"] = str(cfg["mountingplace"]).strip() if cfg["mountingplace"] is not None else "free"
    cfg["optimalangles"] = parse_bool(cfg["optimalangles"], False)
    cfg["angle"] = safe_float(cfg["angle"], 30.0)
    cfg["aspect"] = safe_float(cfg["aspect"], 0.0)
    cfg["tracking_mode"] = str(cfg["tracking_mode"]).strip() if cfg["tracking_mode"] is not None else "fixed"
    cfg["raddatabase"] = str(cfg["raddatabase"]).strip() if cfg["raddatabase"] is not None else "PVGIS-SARAH3"
    min_year, max_year = get_db_year_limits(cfg["raddatabase"])
    cfg["startyear"] = safe_int(cfg["startyear"], min_year)
    cfg["endyear"] = safe_int(cfg["endyear"], max_year)
    cfg["usehorizon"] = parse_bool(cfg["usehorizon"], True)
    cfg["components"] = parse_bool(cfg["components"], True)

    if cfg["lat"] is None or cfg["lon"] is None:
        raise ValueError("Nel foglio configurazione mancano latitudine e/o longitudine.")
    return cfg


def rename_measurement_columns(df: pd.DataFrame) -> pd.DataFrame:
    renamed = df.copy()
    norm_map = {normalize_text(c): c for c in renamed.columns}
    rename_dict = {}

    for target, aliases in MEASURE_ALIASES.items():
        for alias in aliases:
            n = normalize_text(alias)
            if n in norm_map:
                rename_dict[norm_map[n]] = target
                break

    renamed = renamed.rename(columns=rename_dict)
    return renamed


def prepare_measurements_from_sheet(raw_df: pd.DataFrame) -> pd.DataFrame:
    df = rename_measurement_columns(raw_df)

    required = ["year", "month", "day", "hour", "power_kw"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(
            "Il foglio misure deve contenere le colonne anno, mese, giorno, ora e Potenza misurata in kW. "
            f"Mancano: {', '.join(missing)}"
        )

    df = df.copy()
    for c in required:
        df[c] = pd.to_numeric(df[c], errors="coerce")

    df = df.dropna(subset=required).copy()
    if df.empty:
        raise ValueError("Il foglio misure è presente ma non contiene righe valide.")

    df["timestamp_utc"] = pd.to_datetime(
        dict(
            year=df["year"].astype(int),
            month=df["month"].astype(int),
            day=df["day"].astype(int),
            hour=df["hour"].astype(int),
        ),
        errors="coerce",
        utc=True,
    )

    df = df.dropna(subset=["timestamp_utc"]).copy()
    if df.empty:
        raise ValueError("Impossibile costruire timestamp validi dal foglio misure.")

    df["measured_power_kw"] = pd.to_numeric(df["power_kw"], errors="coerce").fillna(0.0)
    df = df.groupby("timestamp_utc", as_index=False)["measured_power_kw"].mean()

    full_index = pd.date_range(
        start=df["timestamp_utc"].min(),
        end=df["timestamp_utc"].max(),
        freq="H",
        tz="UTC",
    )

    df = (
        df.set_index("timestamp_utc")
        .reindex(full_index)
        .rename_axis("timestamp_utc")
        .reset_index()
    )
    df["measured_power_kw"] = pd.to_numeric(df["measured_power_kw"], errors="coerce").fillna(0.0)

    # per serie orarie, kW medi dell'ora ~= kWh nell'ora
    df["measured_energy_kwh"] = df["measured_power_kw"]

    df["year"] = df["timestamp_utc"].dt.year
    df["month"] = df["timestamp_utc"].dt.month
    df["day"] = df["timestamp_utc"].dt.day
    df["hour"] = df["timestamp_utc"].dt.hour
    df["mdh_key"] = df["timestamp_utc"].dt.strftime("%m-%d %H:00")
    return df[["timestamp_utc", "year", "month", "day", "hour", "mdh_key", "measured_power_kw", "measured_energy_kwh"]]


def load_plant_workbook(uploaded_file) -> Dict:
    try:
        xls = pd.ExcelFile(uploaded_file)
    except Exception as exc:
        raise ValueError(f"Il file impianto deve essere un Excel leggibile. Dettaglio: {exc}")

    config_sheet, measure_sheet = detect_sheet_roles(xls)

    if config_sheet is None:
        raise ValueError("File impianto non valido: manca il foglio configurazione.")

    config_df = pd.read_excel(xls, sheet_name=config_sheet)
    if config_df.empty:
        raise ValueError("Il foglio configurazione è vuoto.")

    plant_cfg = parse_plant_config_sheet(config_df)

    measurements_df = None
    measurements_raw = None
    if measure_sheet is not None:
        measurements_raw = read_excel_with_detected_header(
            xls=xls,
            sheet_name=measure_sheet,
            aliases_dict=MEASURE_ALIASES,
            min_found=4,
        )
        if measurements_raw is not None and not measurements_raw.empty:
            measurements_df = prepare_measurements_from_sheet(measurements_raw)

    return {
        "config_sheet_name": config_sheet,
        "measure_sheet_name": measure_sheet,
        "config_raw_df": config_df,
        "measurements_raw_df": measurements_raw,
        "plant_cfg": plant_cfg,
        "measurements_df": measurements_df,
    }


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


def render_request_line(base_url: str, params: Dict) -> str:
    req = requests.Request("GET", base_url, params=params).prepare()
    return req.url


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
        merge_cols = ["timestamp_utc", "measured_energy_kwh"]
        if "measured_power_kw" in monitoring_df.columns:
            merge_cols.append("measured_power_kw")
        out = out.merge(monitoring_df[merge_cols], on="timestamp_utc", how="left")

        out["deviation_kwh"] = out["measured_energy_kwh"] - out["expected_energy_kwh"]
        denom = out["expected_energy_kwh"].replace(0, pd.NA)
        out["deviation_pct"] = (out["deviation_kwh"] / denom) * 100.0
        out["performance_ratio_proxy"] = out["measured_energy_kwh"] / denom
    else:
        out["measured_energy_kwh"] = pd.NA
        out["measured_power_kw"] = pd.NA
        out["deviation_kwh"] = pd.NA
        out["deviation_pct"] = pd.NA
        out["performance_ratio_proxy"] = pd.NA

    out["delta_expected_vs_baseline_kwh"] = out["expected_energy_kwh"] - out.get("baseline_energy_kwh", pd.Series(index=out.index, dtype=float))
    denom_baseline = pd.to_numeric(out.get("baseline_energy_kwh", pd.Series(index=out.index, dtype=float)), errors="coerce").replace(0, pd.NA)
    out["delta_expected_vs_baseline_pct"] = (out["delta_expected_vs_baseline_kwh"] / denom_baseline) * 100.0

    return out


def summarize_kpis(comparison_df: pd.DataFrame, source_name: str, percentile: int) -> pd.DataFrame:
    summary = {
        "source_meteo": source_name,
        "baseline_percentile": percentile,
        "rows_comparison": int(len(comparison_df)),
        "expected_energy_total_kwh": pd.to_numeric(comparison_df["expected_energy_kwh"], errors="coerce").sum(),
        "baseline_energy_total_kwh": pd.to_numeric(comparison_df.get("baseline_energy_kwh"), errors="coerce").sum(),
        "measured_energy_total_kwh": pd.to_numeric(comparison_df["measured_energy_kwh"], errors="coerce").sum(),
        "mean_deviation_pct": pd.to_numeric(comparison_df["deviation_pct"], errors="coerce").mean(),
        "median_deviation_pct": pd.to_numeric(comparison_df["deviation_pct"], errors="coerce").median(),
        "mean_performance_ratio_proxy": pd.to_numeric(comparison_df["performance_ratio_proxy"], errors="coerce").mean(),
        "mean_delta_expected_vs_baseline_pct": pd.to_numeric(comparison_df["delta_expected_vs_baseline_pct"], errors="coerce").mean(),
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
    monitoring_prepared: Optional[pd.DataFrame],
    config_raw_sheet: Optional[pd.DataFrame],
    kpi_df: pd.DataFrame,
) -> bytes:
    buffer = BytesIO()
    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        pd.DataFrame(config_rows).to_excel(writer, sheet_name="INPUT_CONFIG", index=False)
        if config_raw_sheet is not None:
            config_raw_sheet.to_excel(writer, sheet_name="PLANT_CONFIG_RAW", index=False)
        remove_timezone_for_excel(baseline_raw).to_excel(writer, sheet_name="PVGIS_BASELINE_RAW", index=False)
        remove_timezone_for_excel(baseline_percentile).to_excel(writer, sheet_name="PVGIS_BASELINE_PCTL", index=False)
        remove_timezone_for_excel(recent_weather_raw).to_excel(writer, sheet_name="RECENT_WEATHER_RAW", index=False)
        remove_timezone_for_excel(expected_recent).to_excel(writer, sheet_name="EXPECTED_RECENT", index=False)
        remove_timezone_for_excel(comparison_df).to_excel(writer, sheet_name="COMPARISON", index=False)
        if monitoring_raw is not None:
            monitoring_raw.to_excel(writer, sheet_name="MONITORING_RAW", index=False)
        if monitoring_prepared is not None:
            remove_timezone_for_excel(monitoring_prepared).to_excel(writer, sheet_name="MONITORING_PREPARED", index=False)
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

# ----------------------------
# UI helpers - Tower PV Analytics
# ----------------------------
def inject_tpa_style() -> None:
    st.markdown(
        """
        <style>
        .block-container {padding-top: 1.4rem; padding-bottom: 2rem;}
        .tpa-hero {padding: 1.25rem 1.4rem; border-radius: 18px; background: linear-gradient(135deg, #0f172a 0%, #164e63 55%, #166534 100%); color: white; margin-bottom: 1rem; box-shadow: 0 10px 28px rgba(15, 23, 42, 0.18);}
        .tpa-hero h1 {margin: 0; font-size: 2.05rem; letter-spacing: -0.02em;}
        .tpa-hero p {margin: .35rem 0 0 0; color: rgba(255,255,255,.86); font-size: 1.02rem;}
        .tpa-card {padding: 1rem 1.1rem; border: 1px solid rgba(148, 163, 184, .35); border-radius: 16px; background: rgba(255, 255, 255, .72); box-shadow: 0 4px 18px rgba(15, 23, 42, .06); min-height: 120px;}
        .tpa-card h4 {margin: 0 0 .35rem 0; font-size: 1rem;}
        .tpa-card p {margin: 0; color: #475569; font-size: .92rem;}
        .tpa-kpi {padding: .9rem 1rem; border: 1px solid rgba(148, 163, 184, .35); border-radius: 16px; background: white; box-shadow: 0 4px 14px rgba(15, 23, 42, .05);}
        .tpa-kpi-label {font-size: .82rem; color: #64748b; margin-bottom: .25rem;}
        .tpa-kpi-value {font-size: 1.55rem; font-weight: 700; color: #0f172a;}
        .tpa-kpi-note {font-size: .78rem; color: #64748b; margin-top: .18rem;}
        .tpa-section-caption {color: #64748b; margin-top: -0.35rem; margin-bottom: .7rem;}
        </style>
        """, unsafe_allow_html=True)


def render_hero(current_user: Optional[Dict] = None) -> None:
    user_line = f"Connesso come: {current_user['username']}" if current_user else "Accesso riservato"
    st.markdown(f"""<div class="tpa-hero"><h1>{APP_TITLE}</h1><p>{APP_SUBTITLE}</p><p style="font-size:.86rem; opacity:.78; margin-top:.55rem;">{user_line}</p></div>""", unsafe_allow_html=True)


def render_value_card(title: str, body: str) -> None:
    st.markdown(f"""<div class="tpa-card"><h4>{title}</h4><p>{body}</p></div>""", unsafe_allow_html=True)


def metric_value(df: pd.DataFrame, col: str, default=None):
    if df is None or df.empty or col not in df.columns:
        return default
    value = df.iloc[0].get(col, default)
    try:
        if pd.isna(value):
            return default
    except Exception:
        pass
    return value


def fmt_num(value, decimals: int = 1, suffix: str = "") -> str:
    if value is None:
        return "n.d."
    try:
        return f"{float(value):,.{decimals}f}{suffix}".replace(",", "X").replace(".", ",").replace("X", ".")
    except Exception:
        return "n.d."


def render_kpi_card(label: str, value: str, note: str = "") -> None:
    st.markdown(f"""<div class="tpa-kpi"><div class="tpa-kpi-label">{label}</div><div class="tpa-kpi-value">{value}</div><div class="tpa-kpi-note">{note}</div></div>""", unsafe_allow_html=True)


def render_kpi_legend(measurements_present: bool) -> None:
    with st.expander("Come leggere gli indicatori", expanded=False):
        if measurements_present:
            st.markdown("""
**Energia Misurata [kWh]**: somma dell'energia/potenza oraria rilevata nel file misure. In questa versione, il valore medio orario in kW viene assunto numericamente equivalente ai kWh dell'ora.  

**Energia Attesa [kWh]**: produzione stimata usando i dati meteo reali del periodo selezionato e i parametri tecnici dell'impianto.  

**Scostamento Medio [%]**: media degli scostamenti orari tra misurato e atteso. Valori negativi indicano produzione misurata inferiore all'atteso.  

**Indice Prestazione**: rapporto tra energia misurata ed energia attesa. Valori prossimi a 1 indicano comportamento in linea con l'atteso.
            """)
        else:
            st.markdown("""
**Energia Attesa [kWh]**: produzione stimata usando i dati meteo reali del periodo selezionato.  

**Baseline Storica [kWh]**: produzione storica attesa da PVGIS, costruita sul percentile selezionato.  

**Delta vs Baseline [%]**: differenza media tra produzione attesa recente e baseline storica.
            """)


def apply_prefill_to_widget_state(prefill: Dict) -> None:
    mapping = {"codice_impianto": "codice_impianto", "lat": "lat", "lon": "lon", "peakpower": "peakpower", "loss": "loss", "pvtechchoice": "pvtechchoice", "mountingplace": "mountingplace", "optimalangles": "optimalangles", "angle": "angle", "aspect": "aspect", "tracking_mode": "tracking_mode", "raddatabase": "raddatabase", "startyear": "startyear", "endyear": "endyear", "usehorizon": "usehorizon", "components": "components"}
    for cfg_key, widget_key in mapping.items():
        if cfg_key in prefill and prefill[cfg_key] is not None:
            st.session_state[widget_key] = prefill[cfg_key]


def get_default_prefill() -> Dict:
    return {"codice_impianto": "SRB_xxx", "lat": 41.8927524, "lon": 12.4853054, "peakpower": 1.0, "loss": 14.0, "pvtechchoice": "crystSi", "mountingplace": "free", "optimalangles": False, "angle": 30.0, "aspect": 0.0, "tracking_mode": "fixed", "raddatabase": "PVGIS-SARAH3", "startyear": 2005, "endyear": 2023, "usehorizon": True, "components": True}


def format_upload_period(measurements_df: Optional[pd.DataFrame]) -> str:
    if measurements_df is None or measurements_df.empty or "timestamp_utc" not in measurements_df.columns:
        return "n.d."
    start = measurements_df["timestamp_utc"].min()
    end = measurements_df["timestamp_utc"].max()
    return f"{start.strftime('%d/%m/%Y')} - {end.strftime('%d/%m/%Y')}"

def login_ui() -> None:
    inject_tpa_style()
    render_hero(None)
    c1, c2, c3 = st.columns([1.1, 1.2, 1.1])
    with c2:
        st.markdown("### Accesso piattaforma")
        st.caption("Advanced analytics for PV performance verification, baseline comparison and site monitoring.")
        with st.form("login_form"):
            username = st.text_input("Account")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Accedi alla piattaforma", use_container_width=True)
    if submitted:
        user = authenticate(username.strip(), password)
        if user:
            st.session_state["user"] = user
            st.rerun()
        else:
            st.error("Credenziali non valide.")

def admin_ui(current_user: Dict) -> None:
    st.markdown("### Amministrazione Utenti")
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
    st.markdown("### Storico Analisi")
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


def validation_checks(plant_cfg: Dict, baseline_cfg: Dict, recent_cfg: Dict, source_name: str) -> None:
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
                raise ValueError(
                    f"Per Open-Meteo seleziona almeno i parametri obbligatori: {', '.join(OPEN_METEO_MIN_REQUIRED)}."
                )


def render_structure() -> None:
    st.markdown("### Piattaforma")
    c1, c2, c3 = st.columns(3)
    with c1:
        render_value_card("Performance Verification", "Confronta produzione misurata, produzione attesa e baseline storica per verificare le prestazioni del sito.")
    with c2:
        render_value_card("Weather-Normalized Analysis", "Usa dati meteo reali per stimare la produzione attesa nel periodo di analisi.")
    with c3:
        render_value_card("Export & Audit Trail", "Genera report Excel completi e conserva lo storico delle analisi eseguite.")


def app_ui() -> None:
    inject_tpa_style()
    user = st.session_state["user"]
    render_hero(user)

    top_left, top_right = st.columns([5, 1])
    with top_left:
        st.caption("Analisi delle prestazioni fotovoltaiche per siti tower e infrastrutture telecom.")
    with top_right:
        if st.button("Logout", use_container_width=True):
            st.session_state.clear()
            st.rerun()

    render_structure()

    if int(user["is_admin"]) == 1:
        with st.expander("Amministrazione Utenti", expanded=False):
            admin_ui(user)

    with st.expander("Storico Analisi", expanded=False):
        render_runs_ui(user)

    if "plant_prefill" not in st.session_state:
        st.session_state["plant_prefill"] = get_default_prefill()
    prefill = dict(get_default_prefill())
    prefill.update(st.session_state.get("plant_prefill", {}))
    ui_key = st.session_state.get("ui_refresh_id", 0)

    parsed_workbook = st.session_state.get("parsed_workbook")
    measurements_from_file = parsed_workbook.get("measurements_df") if parsed_workbook else None
    config_raw_sheet = parsed_workbook.get("config_raw_df") if parsed_workbook else None
    measurements_raw_sheet = parsed_workbook.get("measurements_raw_df") if parsed_workbook else None

    today_minus_7 = date.today() - timedelta(days=7)
    default_recent_start = today_minus_7 - timedelta(days=2)
    default_recent_end = today_minus_7
    if measurements_from_file is not None and not measurements_from_file.empty:
        default_recent_start = measurements_from_file["timestamp_utc"].min().date()
        default_recent_end = measurements_from_file["timestamp_utc"].max().date()

    st.markdown("### 1. Profilo Sito")
    st.markdown("<div class='tpa-section-caption'>Definisci i parametri tecnici dell'impianto fotovoltaico da analizzare.</div>", unsafe_allow_html=True)
    a1, a2, a3 = st.columns(3)
    with a1:
        codice_impianto = st.text_input("Codice sito", value=str(prefill.get("codice_impianto", "SRB_xxx")), key=f"codice_impianto_{ui_key}")
        lat = st.number_input("Latitudine", value=float(prefill.get("lat", 41.8927524)), format="%.7f", key=f"lat_{ui_key}")
        lon = st.number_input("Longitudine", value=float(prefill.get("lon", 12.4853054)), format="%.7f", key=f"lon_{ui_key}")
        peakpower = st.number_input("Potenza di picco [kWp]", min_value=0.0, value=float(prefill.get("peakpower", 1.0)), step=0.1, key=f"peakpower_{ui_key}")
        loss = st.number_input("Perdite [%]", min_value=0.0, max_value=100.0, value=float(prefill.get("loss", 14.0)), step=0.5, key=f"loss_{ui_key}")
    with a2:
        pvtech_options = ["crystSi", "CIS", "CdTe", "Unknown"]
        pvtech_default = prefill.get("pvtechchoice", "crystSi")
        pvtech_idx = pvtech_options.index(pvtech_default) if pvtech_default in pvtech_options else 0
        pvtechchoice = st.selectbox("Tecnologia pannello", pvtech_options, index=pvtech_idx, key=f"pvtechchoice_{ui_key}")
        mounting_options = ["free", "building"]
        mounting_default = prefill.get("mountingplace", "free")
        mounting_idx = mounting_options.index(mounting_default) if mounting_default in mounting_options else 0
        mountingplace = st.selectbox("Tipo di montaggio", mounting_options, index=mounting_idx, key=f"mountingplace_{ui_key}")
        optimalangles = st.checkbox("Angoli ottimali", value=bool(prefill.get("optimalangles", False)), key=f"optimalangles_{ui_key}")
        angle = st.number_input("Tilt [°]", min_value=0.0, max_value=90.0, value=float(prefill.get("angle", 30.0)), step=1.0, key=f"angle_{ui_key}")
        aspect = st.number_input("Azimut [°]", min_value=-180.0, max_value=180.0, value=float(prefill.get("aspect", 0.0)), step=1.0, key=f"aspect_{ui_key}")
    with a3:
        tracking_options = ["fixed", "trackingtype_horizontal", "trackingtype_tilted", "trackingtype_biaxial"]
        tracking_default = prefill.get("tracking_mode", "fixed")
        tracking_idx = tracking_options.index(tracking_default) if tracking_default in tracking_options else 0
        tracking_mode = st.selectbox("Tracking", tracking_options, index=tracking_idx, key=f"tracking_mode_{ui_key}")
        raddb_options = ["PVGIS-SARAH3", "PVGIS-ERA5", "PVGIS-SARAH2"]
        raddb_default = prefill.get("raddatabase", "PVGIS-SARAH3")
        raddb_idx = raddb_options.index(raddb_default) if raddb_default in raddb_options else 0
        raddatabase = st.selectbox("Radiation database PVGIS", raddb_options, index=raddb_idx, key=f"raddatabase_{ui_key}")
        min_year, max_year = get_db_year_limits(raddatabase)
        start_default = min(max(int(prefill.get("startyear", min_year)), min_year), max_year)
        end_default = min(max(int(prefill.get("endyear", max_year)), min_year), max_year)
        startyear = st.number_input("Anno iniziale baseline", min_value=min_year, max_value=max_year, value=start_default, step=1, key=f"startyear_{ui_key}")
        endyear = st.number_input("Anno finale baseline", min_value=min_year, max_value=max_year, value=end_default, step=1, key=f"endyear_{ui_key}")
        usehorizon = st.checkbox("Use horizon", value=bool(prefill.get("usehorizon", True)), key=f"usehorizon_{ui_key}")
        components = st.checkbox("Radiation components", value=bool(prefill.get("components", True)), key=f"components_{ui_key}")

    st.markdown("### 2. Baseline Storica")
    st.markdown("<div class='tpa-section-caption'>Costruisce il profilo storico atteso tramite PVGIS.</div>", unsafe_allow_html=True)
    scenario = st.selectbox("Scenario baseline", options=["P50 - Scenario medio", "P10 - Scenario conservativo"], index=0, help="P50 rappresenta lo scenario storico mediano. P10 è più conservativo.")
    percentile = 50 if scenario.startswith("P50") else 10

    st.markdown("### 3. Dati Meteo Reali")
    st.markdown("<div class='tpa-section-caption'>Seleziona la fonte meteo usata per stimare la produzione attesa nel periodo di analisi.</div>", unsafe_allow_html=True)
    source_name = st.selectbox("Fonte meteo", ["Open-Meteo", "NASA POWER"], index=0, key=f"weather_source_{ui_key}")
    r1, r2 = st.columns(2)
    with r1:
        recent_start_date = st.date_input("Data iniziale meteo", value=default_recent_start, key=f"recent_start_date_{ui_key}")
    with r2:
        recent_end_date = st.date_input("Data finale meteo", value=default_recent_end, key=f"recent_end_date_{ui_key}")

    if source_name == "Open-Meteo":
        open_meteo_hourly_variables = st.multiselect("Misure orarie da scaricare", options=list(OPEN_METEO_VARIABLE_LABELS.keys()), default=OPEN_METEO_RECOMMENDED_DEFAULT, format_func=lambda x: f"{x} — {OPEN_METEO_VARIABLE_LABELS.get(x, x)}", key=f"open_meteo_vars_{ui_key}", help="Per il calcolo produzione tieni almeno global_tilted_irradiance e temperature_2m.")
        nasa_parameters = []
    else:
        nasa_parameters = st.multiselect("Misure orarie da scaricare", options=list(NASA_PARAMETER_LABELS.keys()), default=["ALLSKY_SFC_SW_DWN", "T2M", "WS10M", "ALLSKY_SFC_SW_DNI", "ALLSKY_SFC_SW_DIFF"], format_func=lambda x: f"{x} — {NASA_PARAMETER_LABELS.get(x, x)}", key=f"nasa_power_vars_{ui_key}", help="Per il calcolo produzione tieni almeno ALLSKY_SFC_SW_DWN e T2M.")
        open_meteo_hourly_variables = []

    st.markdown("### 4. Caricamento Dati")
    st.markdown("<div class='tpa-section-caption'>Carica un file Excel con configurazione sito e, se disponibili, misure orarie di produzione. Il caricamento non avvia automaticamente l'analisi.</div>", unsafe_allow_html=True)
    uploaded_plant_file = st.file_uploader("Trascina qui il file Excel o selezionalo dal computer", type=["xlsx", "xls"], key="plant_workbook_uploader")
    if uploaded_plant_file is not None:
        token = f"{uploaded_plant_file.name}_{uploaded_plant_file.size}"
        if st.session_state.get("last_upload_token") != token:
            try:
                parsed_workbook = load_plant_workbook(uploaded_plant_file)
                st.session_state["parsed_workbook"] = parsed_workbook
                st.session_state["plant_prefill"] = parsed_workbook["plant_cfg"]
                st.session_state["last_upload_token"] = token
                st.session_state["ui_refresh_id"] = st.session_state.get("ui_refresh_id", 0) + 1
                st.success("File caricato correttamente. I parametri della UI sono stati aggiornati.")
                st.rerun()
            except Exception as exc:
                st.error(f"Errore nel file impianto: {exc}")
                return

    parsed_workbook = st.session_state.get("parsed_workbook")
    measurements_from_file = parsed_workbook.get("measurements_df") if parsed_workbook else None
    config_raw_sheet = parsed_workbook.get("config_raw_df") if parsed_workbook else None
    measurements_raw_sheet = parsed_workbook.get("measurements_raw_df") if parsed_workbook else None
    if parsed_workbook is not None:
        st.success(f"File pronto. Foglio configurazione: {parsed_workbook['config_sheet_name']}. " + (f"Foglio misure: {parsed_workbook['measure_sheet_name']}." if parsed_workbook.get("measure_sheet_name") is not None else "Foglio misure non presente: verrà eseguito solo il confronto atteso vs baseline."))
        info_cols = st.columns(3)
        with info_cols[0]:
            st.metric("Sito da file", str(parsed_workbook["plant_cfg"].get("codice_impianto", "n.d.")))
        with info_cols[1]:
            st.metric("Righe misure", 0 if measurements_from_file is None else len(measurements_from_file))
        with info_cols[2]:
            st.metric("Periodo misure", format_upload_period(measurements_from_file))

    st.markdown("### 5. Avvio Analisi")
    st.caption("Se il file misure è presente verrà eseguito il confronto Reale vs Atteso. In assenza di misure verrà generata una simulazione Atteso vs Baseline.")
    btn_col, _ = st.columns([1, 3])
    with btn_col:
        submit = st.button("Avvia Analisi Prestazioni", type="primary", use_container_width=False)
    if not submit:
        return

    try:
        plant_cfg = {"codice_impianto": codice_impianto, "lat": float(lat), "lon": float(lon), "peakpower": float(peakpower), "loss": float(loss), "pvtechchoice": pvtechchoice, "mountingplace": mountingplace, "optimalangles": bool(optimalangles), "angle": float(angle), "aspect": float(aspect), "tracking_mode": tracking_mode, "raddatabase": raddatabase, "usehorizon": bool(usehorizon), "components": bool(components)}
        baseline_cfg = {"startyear": int(startyear), "endyear": int(endyear), "percentile": int(percentile)}
        recent_cfg = {"start_date": recent_start_date, "end_date": recent_end_date, "nasa_parameters": nasa_parameters, "open_meteo_hourly_variables": open_meteo_hourly_variables}
        validation_checks(plant_cfg, baseline_cfg, recent_cfg, source_name)
        progress = st.progress(0, text="Validazione input completata")
        status = st.empty()
        pvgis_cfg = dict(plant_cfg)
        pvgis_cfg.update({"startyear": baseline_cfg["startyear"], "endyear": baseline_cfg["endyear"]})
        if source_name == "Open-Meteo":
            meteo_request_params = build_open_meteo_params(recent_cfg, plant_cfg["lat"], plant_cfg["lon"], plant_cfg["angle"], plant_cfg["aspect"])
            meteo_request_line = render_request_line(OPEN_METEO_ARCHIVE_URL, meteo_request_params)
        else:
            nasa_cfg = {"parameters": recent_cfg["nasa_parameters"], "start_date": recent_cfg["start_date"], "end_date": recent_cfg["end_date"]}
            meteo_request_params = build_nasa_params(nasa_cfg, plant_cfg["lat"], plant_cfg["lon"])
            meteo_request_line = render_request_line(NASA_BASE_URL, meteo_request_params)
        with st.expander("Traccia chiamate API", expanded=False):
            trace_text = "Chiamata PVGIS\n" + f"{render_request_line(PVGIS_BASE_URL, build_pvgis_params(pvgis_cfg))}\n\n" + f"Fonte recente: {source_name}\n" + f"{meteo_request_line}"
            st.code(trace_text, language=None)
        status.info("1/5 - Scarico baseline PVGIS")
        baseline_raw = fetch_pvgis_hourly(pvgis_cfg)
        baseline_percentile = aggregate_pvgis_baseline(baseline_raw, percentile=baseline_cfg["percentile"], plant_code=plant_cfg["codice_impianto"])
        progress.progress(20, text="Baseline PVGIS pronta")
        status.info(f"2/5 - Scarico meteo reale da {source_name}")
        if source_name == "Open-Meteo":
            recent_weather_raw = fetch_open_meteo_hourly(recent_cfg, plant_cfg["lat"], plant_cfg["lon"], plant_cfg["angle"], plant_cfg["aspect"])
        else:
            recent_weather_raw = fetch_nasa_hourly(nasa_cfg, plant_cfg["lat"], plant_cfg["lon"])
        progress.progress(45, text="Meteo reale scaricato")
        status.info("3/5 - Calcolo produzione attesa")
        expected_recent = compute_expected_from_recent_weather(recent_weather_raw, plant_cfg, source_name)
        progress.progress(65, text="Produzione attesa calcolata")
        status.info("4/5 - Preparo misure da file impianto")
        monitoring_prepared = measurements_from_file
        monitoring_raw = measurements_raw_sheet
        if monitoring_prepared is None:
            st.info("Nessun foglio misure disponibile: verrà prodotto solo il confronto tra atteso e baseline.")
        progress.progress(82, text="Misure preparate")
        status.info("5/5 - Costruisco risultati, indicatori ed Excel")
        comparison_df = compare_expected_vs_measured(expected_recent, monitoring_prepared, baseline_percentile)
        kpi_df = summarize_kpis(comparison_df, source_name, int(percentile))
        config_rows = [{"section": "plant", "key": k, "value": v} for k, v in plant_cfg.items()] + [{"section": "baseline", "key": k, "value": v} for k, v in baseline_cfg.items()] + [{"section": "recent_weather", "key": k, "value": v.isoformat() if hasattr(v, "isoformat") else v} for k, v in recent_cfg.items()] + [{"section": "run", "key": "generated_at_utc", "value": datetime.utcnow().isoformat()}, {"section": "run", "key": "user", "value": user["username"]}, {"section": "run", "key": "weather_source", "value": source_name}, {"section": "run", "key": "measurements_present", "value": monitoring_prepared is not None}, {"section": "run", "key": "measurements_holes_filled_with_zero", "value": True if monitoring_prepared is not None else None}]
        output_name = build_run_filename(codice_impianto, source_name, int(percentile))
        excel_bytes = to_excel_bytes(config_rows=config_rows, baseline_raw=baseline_raw, baseline_percentile=baseline_percentile, recent_weather_raw=recent_weather_raw, expected_recent=expected_recent, comparison_df=comparison_df, monitoring_raw=monitoring_raw, monitoring_prepared=monitoring_prepared, config_raw_sheet=config_raw_sheet, kpi_df=kpi_df)
        progress.progress(100, text="Elaborazione completata")
        status.success("Report pronto")
        measurements_present = monitoring_prepared is not None and not monitoring_prepared.empty
        st.markdown("## Risultati Analisi Prestazioni Impianto")
        st.markdown("### Sintesi Prestazioni Impianto")
        k1, k2, k3, k4 = st.columns(4)
        if measurements_present:
            with k1: render_kpi_card("Energia Misurata", fmt_num(metric_value(kpi_df, "measured_energy_total_kwh"), 1, " kWh"), "Produzione rilevata")
            with k2: render_kpi_card("Energia Attesa", fmt_num(metric_value(kpi_df, "expected_energy_total_kwh"), 1, " kWh"), "Stima meteo reale")
            with k3: render_kpi_card("Scostamento Medio", fmt_num(metric_value(kpi_df, "mean_deviation_pct"), 1, "%"), "Misurato vs atteso")
            with k4: render_kpi_card("Indice Prestazione", fmt_num(metric_value(kpi_df, "mean_performance_ratio_proxy"), 2, ""), "Target ≈ 1")
        else:
            with k1: render_kpi_card("Energia Attesa", fmt_num(metric_value(kpi_df, "expected_energy_total_kwh"), 1, " kWh"), "Stima meteo reale")
            with k2: render_kpi_card("Baseline Storica", fmt_num(metric_value(kpi_df, "baseline_energy_total_kwh"), 1, " kWh"), "PVGIS percentile")
            with k3: render_kpi_card("Delta vs Baseline", fmt_num(metric_value(kpi_df, "mean_delta_expected_vs_baseline_pct"), 1, "%"), "Atteso recente vs storico")
            with k4: render_kpi_card("Ore Analizzate", fmt_num(metric_value(kpi_df, "rows_comparison"), 0, ""), "Periodo selezionato")
        render_kpi_legend(measurements_present)
        with st.expander("Tabella indicatori tecnici", expanded=measurements_present):
            st.dataframe(kpi_df, use_container_width=True)
        st.markdown("### Produzione Oraria: Misurata vs Attesa vs Baseline")
        chart_df = comparison_df.copy().sort_values("timestamp_utc")
        chart_cols = [c for c in ["expected_energy_kwh", "baseline_energy_kwh", "measured_energy_kwh"] if c in chart_df.columns]
        if chart_cols:
            line_df = chart_df[["timestamp_utc"] + chart_cols].set_index("timestamp_utc")
            st.line_chart(line_df, height=380)
        else:
            st.info("Non ci sono abbastanza dati per il grafico orario.")
        if measurements_present and "deviation_pct" in comparison_df.columns:
            st.markdown("### Scostamento Percentuale Orario")
            dev_df = chart_df[["timestamp_utc", "deviation_pct"]].set_index("timestamp_utc")
            st.line_chart(dev_df, height=260)
        st.markdown("### Dettaglio Orario Analisi")
        view_cols = [c for c in ["timestamp_utc", "expected_energy_kwh", "baseline_energy_kwh", "delta_expected_vs_baseline_pct", "measured_power_kw", "measured_energy_kwh", "deviation_pct", "performance_ratio_proxy", "irradiance_proxy_wm2", "temp_air_c", "expected_method", "baseline_power_w", "baseline_Gi_wm2"] if c in comparison_df.columns]
        rename_view = {"timestamp_utc": "Data/Ora UTC", "expected_energy_kwh": "Energia Attesa [kWh]", "baseline_energy_kwh": "Baseline [kWh]", "delta_expected_vs_baseline_pct": "Delta vs Baseline [%]", "measured_power_kw": "Potenza Misurata [kW]", "measured_energy_kwh": "Energia Misurata [kWh]", "deviation_pct": "Scostamento [%]", "performance_ratio_proxy": "Indice Prestazione", "irradiance_proxy_wm2": "Irraggiamento proxy [W/m²]", "temp_air_c": "Temperatura aria [°C]", "expected_method": "Metodo atteso", "baseline_power_w": "Baseline power [W]", "baseline_Gi_wm2": "Baseline Gi [W/m²]"}
        st.dataframe(comparison_df[view_cols].rename(columns=rename_view).head(200), use_container_width=True)
        saved_path = save_run_record(username=user["username"], plant_code=codice_impianto, weather_source=source_name, percentile=int(percentile), output_filename=output_name, output_bytes=excel_bytes, kpi_df=kpi_df)
        st.caption(f"Analisi salvata: {saved_path}")
        st.download_button("Scarica Report Excel", data=excel_bytes, file_name=output_name, mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", use_container_width=True)
        with st.expander("Note metodologiche"):
            st.write("Open-Meteo usa GTI oraria se disponibile; NASA POWER usa GHI come proxy semplice dell'irraggiamento sul piano. La baseline PVGIS viene convertita da P [W] a baseline_energy_kwh su base oraria dividendo per 1000. Le misure del file impianto sono lette come Potenza misurata [kW] oraria: i buchi dell'intervallo vengono riempiti con zero. Per il confronto orario, kW medi orari e kWh dell'ora vengono assunti numericamente equivalenti.")
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
