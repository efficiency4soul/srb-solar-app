import os
import json
import sqlite3
import smtplib
import ssl
import secrets
import hashlib
from email.message import EmailMessage
from io import BytesIO
from datetime import date, datetime, timedelta
from typing import Dict, List, Optional, Tuple

import pandas as pd
import requests
import streamlit as st

APP_TITLE = "SRB Solar Production App"
DB_PATH = "users.db"
PVGIS_BASE_URL = "https://re.jrc.ec.europa.eu/api/v5_3/seriescalc"
NASA_BASE_URL = "https://power.larc.nasa.gov/api/temporal/hourly/point"
DEFAULT_OUTPUT_NAME = "srb_solar_output.xlsx"
REQUEST_TIMEOUT = 60
PVGIS_DB_YEAR_LIMITS = {
    "PVGIS-SARAH2": (2005, 2020),
    "PVGIS-SARAH3": (2005, 2023),
    "PVGIS-ERA5": (2005, 2023),
    "PVGIS-SARAH": (2005, 2016),
}


# ----------------------------
# Authentication helpers
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
    msg["Subject"] = "Credenziali di accesso - SRB Solar Production App"
    msg["From"] = smtp_sender
    msg["To"] = email
    msg.set_content(
        f"""Buongiorno,

sono state create le credenziali per accedere a {APP_TITLE}.

Username: {username}
Password: {password}

Si consiglia di modificare la password al primo utilizzo.
"""
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
# API helpers
# ----------------------------
def normalize_pvgis_raddatabase(selected: str) -> str:
    mapping = {
        "PVGIS-SARAH2": "PVGIS-SARAH2",
        "PVGIS-SARAH3": "PVGIS-SARAH3",
        "PVGIS-SARAH": "PVGIS-SARAH",
        "PVGIS-ERA5": "PVGIS-ERA5",
    }
    return mapping.get(selected, selected)


def get_db_year_limits(raddatabase: str) -> Tuple[int, int]:
    normalized = normalize_pvgis_raddatabase(raddatabase)
    return PVGIS_DB_YEAR_LIMITS.get(normalized, (2005, 2023))


def build_pvgis_params(cfg: Dict) -> Dict:
    trackingtype = 0
    if cfg["tracking_mode"] == "trackingtype_horizontal":
        trackingtype = 1
    elif cfg["tracking_mode"] == "trackingtype_biaxial":
        trackingtype = 2
    elif cfg["tracking_mode"] == "trackingtype_tilted":
        trackingtype = 5

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
        "trackingtype": trackingtype,
        "angle": cfg["angle"],
        "aspect": cfg["aspect"],
        "optimalangles": int(cfg["optimalangles"]),
        "usehorizon": int(cfg["usehorizon"]),
        "components": int(cfg["components"]),
        "outputformat": "json",
    }
    if cfg.get("raddatabase"):
        params["raddatabase"] = normalize_pvgis_raddatabase(cfg["raddatabase"])
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
    parameters = ",".join(cfg["parameters"])
    return {
        "parameters": parameters,
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

    df = pd.concat(series, axis=1).reset_index().rename(columns={"index": "nasa_time_key"})
    df["timestamp_utc"] = pd.to_datetime(df["nasa_time_key"], format="%Y%m%d%H", utc=True)
    df["month"] = df["timestamp_utc"].dt.month
    df["day"] = df["timestamp_utc"].dt.day
    df["hour"] = df["timestamp_utc"].dt.hour
    df["mdh_key"] = df["timestamp_utc"].dt.strftime("%m-%d %H:00")
    return df


# ----------------------------
# Transformation helpers
# ----------------------------
def pick_percentile_value(percentile: float) -> float:
    p = float(percentile)
    if p > 1:
        p = p / 100.0
    if p < 0 or p > 1:
        raise ValueError("Il percentile deve essere compreso tra 0 e 100.")
    return p


def aggregate_pvgis_percentile(df: pd.DataFrame, percentile: float, plant_code: str) -> pd.DataFrame:
    p = pick_percentile_value(percentile)
    numeric_cols = [c for c in df.columns if c not in {"time", "timestamp_utc", "year", "month", "day", "hour", "mdh_key"}]
    numeric_cols = [c for c in numeric_cols if pd.api.types.is_numeric_dtype(df[c])]
    if not numeric_cols:
        raise ValueError("Nessuna colonna numerica PVGIS disponibile per il calcolo del percentile.")

    grouped = df.groupby(["month", "day", "hour"], dropna=False)
    agg = grouped[numeric_cols].quantile(p).reset_index()
    agg["analysis_timestamp"] = pd.to_datetime(
        {
            "year": 2020,
            "month": agg["month"],
            "day": agg["day"],
            "hour": agg["hour"],
        },
        utc=True,
        errors="coerce",
    )
    agg = agg.dropna(subset=["analysis_timestamp"]).sort_values("analysis_timestamp").reset_index(drop=True)
    agg["mdh_key"] = agg["analysis_timestamp"].dt.strftime("%m-%d %H:00")
    agg.insert(0, "codice_impianto", plant_code)
    agg.insert(1, "percentile", p)
    return agg


def merge_with_nasa(pvgis_percentile_df: pd.DataFrame, nasa_df: pd.DataFrame) -> pd.DataFrame:
    nasa_cols = [c for c in nasa_df.columns if c not in {"nasa_time_key", "timestamp_utc", "month", "day", "hour"}]
    nasa_small = nasa_df[nasa_cols].drop_duplicates(subset=["mdh_key"])
    merged = pvgis_percentile_df.merge(nasa_small, on="mdh_key", how="left", suffixes=("", "_NASA"))
    return merged


def _remove_timezone_for_excel(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for col in df.columns:
        col_dtype = df[col].dtype
        if isinstance(col_dtype, pd.DatetimeTZDtype):
            df[col] = df[col].dt.tz_localize(None)
    return df


def to_excel_bytes(output_df: pd.DataFrame, pvgis_raw: pd.DataFrame, nasa_raw: pd.DataFrame, meta: Dict) -> bytes:
    output_df_excel = _remove_timezone_for_excel(output_df)
    pvgis_raw_excel = _remove_timezone_for_excel(pvgis_raw)
    nasa_raw_excel = _remove_timezone_for_excel(nasa_raw)

    buffer = BytesIO()
    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        output_df_excel.to_excel(writer, sheet_name="OUTPUT", index=False)
        pvgis_raw_excel.to_excel(writer, sheet_name="PVGIS_RAW", index=False)
        nasa_raw_excel.to_excel(writer, sheet_name="NASA_RAW", index=False)
        meta_df = pd.DataFrame([{"chiave": k, "valore": json.dumps(v) if isinstance(v, (dict, list)) else v} for k, v in meta.items()])
        meta_df.to_excel(writer, sheet_name="META", index=False)
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
        user = authenticate(username, password)
        if user:
            st.session_state["user"] = user
            st.rerun()
        else:
            st.error("Credenziali non valide.")


def admin_ui() -> None:
    st.markdown("---")
    st.subheader("Amministrazione utenti")

    with st.expander("Crea nuova utenza", expanded=False):
        with st.form("create_user_form"):
            col1, col2 = st.columns(2)
            with col1:
                new_username = st.text_input("Nuovo account")
                new_email = st.text_input("Email")
            with col2:
                new_password = st.text_input("Password iniziale", type="password")
                new_is_admin = st.checkbox("Utente amministratore")
            create_submitted = st.form_submit_button("Crea utente e invia credenziali")

        if create_submitted:
            try:
                create_user(new_username.strip(), new_email.strip(), new_password, new_is_admin)
                ok, message = send_credentials_email(new_username.strip(), new_email.strip(), new_password)
                if ok:
                    st.success(message)
                else:
                    st.warning(message)
            except sqlite3.IntegrityError:
                st.error("Username già presente.")
            except Exception as exc:
                st.error(f"Errore nella creazione utente: {exc}")

    users_df = list_users()
    st.dataframe(users_df, use_container_width=True)

    with st.expander("Modifica o cancella utenza", expanded=False):
        if users_df.empty:
            st.info("Nessuna utenza disponibile.")
        else:
            username_options = {f"{row['username']} ({row['email']})": int(row['id']) for _, row in users_df.iterrows()}
            selected_label = st.selectbox("Seleziona utenza", list(username_options.keys()))
            selected_id = username_options[selected_label]
            selected_row = users_df.loc[users_df["id"] == selected_id].iloc[0]

            with st.form("edit_user_form"):
                e1, e2 = st.columns(2)
                with e1:
                    edit_username = st.text_input("Username", value=str(selected_row["username"]))
                    edit_email = st.text_input("Email", value=str(selected_row["email"]))
                with e2:
                    edit_password = st.text_input("Nuova password (lascia vuoto per non cambiarla)", type="password")
                    edit_is_admin = st.checkbox("Utente amministratore", value=bool(selected_row["is_admin"]))

                save_col, delete_col = st.columns(2)
                with save_col:
                    save_submitted = st.form_submit_button("Salva modifiche")
                with delete_col:
                    delete_submitted = st.form_submit_button("Cancella utenza")

            if save_submitted:
                try:
                    update_user(selected_id, edit_username.strip(), edit_email.strip(), edit_is_admin, edit_password)
                    if st.session_state["user"].get("id") == selected_id:
                        st.session_state["user"] = authenticate(edit_username.strip(), edit_password or st.session_state["user"].get("password_plain", "")) or st.session_state["user"]
                    st.success("Utenza aggiornata correttamente.")
                    st.rerun()
                except sqlite3.IntegrityError:
                    st.error("Username già presente.")
                except Exception as exc:
                    st.error(f"Errore nell'aggiornamento utente: {exc}")

            if delete_submitted:
                try:
                    delete_user(selected_id, int(st.session_state["user"]["id"]))
                    st.success("Utenza cancellata correttamente.")
                    st.rerun()
                except Exception as exc:
                    st.error(f"Errore nella cancellazione utente: {exc}")


def app_ui() -> None:
    st.title(APP_TITLE)
    user = st.session_state["user"]
    st.caption(f"Connesso come: {user['username']}")

    top1, top2 = st.columns([1, 1])
    with top1:
        if st.button("Logout"):
            st.session_state.clear()
            st.rerun()
    with top2:
        st.write("")

    if int(user["is_admin"]) == 1:
        admin_ui()

    st.markdown("---")
    st.subheader("Configurazione input")

    today_minus_7 = date.today() - timedelta(days=7)

    with st.form("solar_form"):
        st.markdown("### Sezione A — Configurazione PVGIS")
        c1, c2, c3 = st.columns(3)
        with c1:
            codice_impianto = st.text_input("Codice impianto", value="SRB_xxx")
            lat = st.number_input("Latitudine", value=41.8927524, format="%.7f")
            lon = st.number_input("Longitudine", value=12.4853054, format="%.7f")
            peakpower = st.number_input("Peak power [kWp]", min_value=0.0, value=1.0, step=0.1)
            loss = st.number_input("Loss [%]", min_value=0.0, max_value=100.0, value=14.0, step=0.5)
        with c2:
            pvtechchoice = st.selectbox("Tecnologia pannello", ["crystSi", "crystSi2025", "CIS", "CdTe", "Unknown"], index=0)
            mountingplace = st.selectbox("Tipo di montaggio", ["free", "building"], index=0)
            optimalangles = st.checkbox("Optimal angles", value=False)
            angle = st.number_input("Angle [°]", min_value=0.0, max_value=90.0, value=30.0, step=1.0)
            aspect = st.number_input("Aspect [°]", min_value=-180.0, max_value=180.0, value=0.0, step=1.0)
        with c3:
            raddatabase = st.selectbox("Radiation database", ["PVGIS-SARAH3", "PVGIS-SARAH2", "PVGIS-ERA5", "PVGIS-SARAH"], index=0)
            db_year_min, db_year_max = get_db_year_limits(raddatabase)
            tracking_mode = st.selectbox(
                "Tracking",
                ["fixed", "trackingtype_horizontal", "trackingtype_tilted", "trackingtype_biaxial"],
                index=0,
            )
            startyear = st.number_input("Anno iniziale", min_value=db_year_min, max_value=db_year_max, value=db_year_min, step=1)
            endyear = st.number_input("Anno finale", min_value=db_year_min, max_value=db_year_max, value=db_year_max, step=1)
            usehorizon = st.checkbox("Use horizon", value=True)
            components = st.checkbox("Radiation components", value=True)
            st.caption(f"Range disponibile per {raddatabase}: {db_year_min}–{db_year_max}")

        st.markdown("### Sezione B — Configurazione NASA POWER")
        nasa_parameters = st.multiselect(
            "Parametri NASA orari",
            [
                "ALLSKY_SFC_SW_DWN",
                "CLRSKY_SFC_SW_DWN",
                "ALLSKY_SFC_SW_DNI",
                "ALLSKY_SFC_SW_DIFF",
                "T2M",
                "WS10M",
            ],
            default=[
                "ALLSKY_SFC_SW_DWN",
                "CLRSKY_SFC_SW_DWN",
                "ALLSKY_SFC_SW_DNI",
                "ALLSKY_SFC_SW_DIFF",
                "T2M",
                "WS10M",
            ],
        )
        n1, n2 = st.columns(2)
        with n1:
            nasa_start_date = st.date_input("Data iniziale NASA", value=today_minus_7)
        with n2:
            nasa_end_date = st.date_input("Data finale NASA", value=today_minus_7)

        st.markdown("### Sezione C — Percentile Produzione")
        percentile = st.selectbox("Percentile", [10, 50], index=1)

        submit = st.form_submit_button("INVIO DATI E GENERA OUTPUT")

    if submit:
        try:
            if startyear > endyear:
                raise ValueError("L'anno iniziale PVGIS non può essere maggiore dell'anno finale.")
            if nasa_start_date > nasa_end_date:
                raise ValueError("La data iniziale NASA non può essere successiva alla data finale.")
            if not nasa_parameters:
                raise ValueError("Seleziona almeno un parametro NASA POWER.")

            db_min, db_max = get_db_year_limits(raddatabase)
            if startyear < db_min or endyear > db_max:
                raise ValueError(f"Per {raddatabase} gli anni consentiti sono da {db_min} a {db_max}.")

            pvgis_cfg = {
                "codice_impianto": codice_impianto,
                "lat": lat,
                "lon": lon,
                "peakpower": peakpower,
                "loss": loss,
                "pvtechchoice": pvtechchoice,
                "mountingplace": mountingplace,
                "optimalangles": optimalangles,
                "angle": angle,
                "aspect": aspect,
                "tracking_mode": tracking_mode,
                "raddatabase": raddatabase,
                "startyear": int(startyear),
                "endyear": int(endyear),
                "usehorizon": usehorizon,
                "components": components,
            }
            nasa_cfg = {
                "parameters": nasa_parameters,
                "start_date": nasa_start_date,
                "end_date": nasa_end_date,
            }

            progress = st.progress(0, text="Preparazione elaborazione...")
            status = st.empty()

            status.info("1/4 — Scarico dati PVGIS")
            pvgis_raw = fetch_pvgis_hourly(pvgis_cfg)
            progress.progress(25, text="PVGIS completato")

            status.info("2/4 — Scarico dati NASA POWER")
            nasa_raw = fetch_nasa_hourly(nasa_cfg, lat=lat, lon=lon)
            progress.progress(50, text="NASA completato")

            status.info("3/4 — Calcolo percentile PVGIS")
            pvgis_output = aggregate_pvgis_percentile(pvgis_raw, percentile=float(percentile), plant_code=codice_impianto)
            progress.progress(75, text="Percentile completato")

            status.info("4/4 — Allineamento dati e generazione Excel")
            final_output = merge_with_nasa(pvgis_output, nasa_raw)

            meta = {
                "generated_at_utc": datetime.utcnow().isoformat(),
                "user": user["username"],
                "pvgis_api_version": "v5_3",
                "pvgis_config": pvgis_cfg,
                "nasa_config": {
                    **nasa_cfg,
                    "start_date": nasa_cfg["start_date"].isoformat(),
                    "end_date": nasa_cfg["end_date"].isoformat(),
                },
                "output_file": DEFAULT_OUTPUT_NAME,
            }

            excel_bytes = to_excel_bytes(final_output, pvgis_raw, nasa_raw, meta)
            progress.progress(100, text="Elaborazione completata")
            status.success("Elaborazione completata correttamente.")
            st.dataframe(final_output.head(50), use_container_width=True)
            st.download_button(
                "Scarica Excel di output",
                data=excel_bytes,
                file_name=DEFAULT_OUTPUT_NAME,
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
        except requests.HTTPError as exc:
            body = exc.response.text[:1000] if exc.response is not None else str(exc)
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
