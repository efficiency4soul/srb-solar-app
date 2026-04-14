# SRB Solar Production App

Web app Streamlit con:
- autenticazione semplice con account/password
- pannello admin per creazione utenti
- invio credenziali via email al momento della creazione
- chiamate a PVGIS JRC e NASA POWER
- calcolo percentile orario PVGIS sul periodo selezionato
- allineamento dei dati NASA sui riferimenti orari mese-giorno-ora
- export Excel `srb_solar_output.xlsx`

## Avvio rapido

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

## Credenziali bootstrap admin

Se il database `users.db` non esiste, al primo avvio viene creato automaticamente un admin iniziale.

Variabili opzionali:

```bash
export BOOTSTRAP_ADMIN_USERNAME=admin
export BOOTSTRAP_ADMIN_EMAIL=admin@example.com
export BOOTSTRAP_ADMIN_PASSWORD=admin123!
```

Se non imposti nulla, usa questi default temporanei:
- username: `admin`
- password: `admin123!`

## Configurazione SMTP per invio credenziali

```bash
export SMTP_HOST=smtp.example.com
export SMTP_PORT=587
export SMTP_USERNAME=user@example.com
export SMTP_PASSWORD=yourpassword
export SMTP_SENDER=no-reply@example.com
export SMTP_USE_TLS=true
```

Senza SMTP configurato, l'utente viene creato ma l'email non viene inviata.

## Note implementative

### PVGIS
L'app usa l'endpoint:
- `https://re.jrc.ec.europa.eu/api/v5_2/seriescalc`

Viene richiesto `outputformat=json` e `pvcalculation=1`.

### NASA POWER
L'app usa l'endpoint:
- `https://power.larc.nasa.gov/api/temporal/hourly/point`

Richiede dati orari con `community=RE` e `time-standard=UTC`.

## Struttura output Excel

Foglio `OUTPUT`
- dati PVGIS aggregati al percentile scelto
- dati NASA affiancati sulle stesse righe tramite chiave `mese-giorno-ora`

Foglio `PVGIS_RAW`
- output orario grezzo PVGIS

Foglio `NASA_RAW`
- output orario grezzo NASA POWER

Foglio `META`
- parametri usati e metadati di generazione

## Limiti attuali

- L'invio email richiede SMTP esterno.
- L'allineamento NASA avviene su chiave `MM-DD HH:00`. Se il periodo NASA non copre tutto l'anno, le ore non presenti restano vuote.
- Il percentile PVGIS è calcolato su tutte le colonne numeriche restituite dall'API per ciascun `mese-giorno-ora`.
