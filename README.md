# SRB Solar Verification App

Web app Streamlit per verificare la produzione misurata di un impianto FV confrontandola con:

1. baseline storica PVGIS multi-anno
2. meteo reale recente
3. produzione attesa recente calcolata dall'irraggiamento

## Struttura funzionale

- **A. Configurazione impianto**
  - coordinate
  - potenza di picco
  - perdite
  - tecnologia modulo
  - tilt / azimut / tracking
- **B. Baseline storica PVGIS**
  - database radiazione
  - anni baseline
  - percentile P10 o P50
- **C. Meteo reale recente**
  - Open-Meteo oppure NASA POWER
  - periodo recente da verificare
- **D. Dati monitoraggio**
  - upload CSV/Excel
  - mapping colonna timestamp
  - mapping colonna produzione misurata
- **E. Output**
  - confronto atteso vs misurato
  - KPI sintetici
  - export Excel multi-sheet

## Logica di calcolo

- PVGIS costruisce la baseline storica per ciascun blocco mese-giorno-ora.
- Open-Meteo o NASA forniscono i dati orari recenti.
- La produzione attesa recente viene stimata in modo semplificato con:

`E_attesa ≈ Pnom * (irradianza_proxy / 1000) * fattore_temperatura * (1 - loss)`

### Fonte meteo consigliata
- **Open-Meteo**: consigliata per il confronto recente, perché l'app usa `global_tilted_irradiance` e quindi è più coerente con l'inclinazione dei moduli.
- **NASA POWER**: disponibile come alternativa, ma nell'app usa una proxy semplice su GHI e quindi è meno robusta per impianti inclinati.

## Fogli Excel prodotti

- `INPUT_CONFIG`
- `PVGIS_BASELINE_RAW`
- `PVGIS_BASELINE_PCTL`
- `RECENT_WEATHER_RAW`
- `EXPECTED_RECENT`
- `COMPARISON`
- `MONITORING_RAW` (se caricato)
- `KPI_SUMMARY`

## Avvio locale

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

## Credenziali iniziali

- username: `admin`
- password: `admin123!`

## Limiti attuali

- il modello di produzione attesa è volutamente semplice e trasparente
- per NASA POWER l'irraggiamento sul piano non è ricostruito con un modello geometrico completo
- per validazioni molto rigorose conviene introdurre in futuro un modello POA più avanzato e uno storico elaborazioni in database
