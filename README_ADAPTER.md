# Python Adapter (CLI) Integration

This repository includes a small Python adapter (`log_adapter.py`) that accepts CICFlowMeter flow posts (JSON or raw CSV lines) and forwards batched JSON payloads to a model/webhook endpoint with the schema:

```json
{ "client_id": "demo-client-0001", "flows": [ { ... }, ... ] }
```

Use the adapter for quick end-to-end testing (recommended) or as a lightweight bridge to your ML service.

- **Endpoints:**
  - `POST /receive_log` — receive flow logs (MainCLI posts here). Accepts JSON like `{ "log": "..." }` or raw CSV text.
  - `GET  /health` — returns `{'status':'ok','buffer':N}` when the adapter is ready.

- **Important environment variables** (all optional; shown with defaults):
  - `MODEL_URL` — URL to forward batched payloads (default: `https://webhook.site/....`).
  - `CLIENT_ID` — client identifier in payloads (default: `demo-client-0001`).
  - `PORT` — HTTP port to listen on (default: `9001`).
  - `BATCH_SIZE` — number of flows per forwarded batch (default: `10`).
  - `BATCH_TIMEOUT` — seconds before flushing a non-full batch (default: `2.0`).
  - `MAX_SEND` — optional total-forward limit (useful for tests; set to `10` to forward exactly ten flows then exit).

Files the adapter writes for debugging:
- `last_sent_payload.json` — last forwarded JSON payload (atomic write).
- `last_bad_rows.log` — any malformed rows that could not be parsed.

Quick PowerShell example (open two shells):

1) Start the adapter (shell #1). Set `MAX_SEND=10` to stop after 10 forwarded flows for verification:

```powershell
# Optional env vars (uncomment to set)
#$env:MODEL_URL = 'https://webhook.site/68560c50-0f72-4a51-942f-984216e99aa9'
#$env:CLIENT_ID = 'demo-client-0001'
#$env:BATCH_SIZE = '10'
#$env:MAX_SEND = '10'
# Start adapter (foreground)
python .\log_adapter.py
```

2) Wait for adapter readiness (shell #1 shows logs) or poll `/health` from another shell (shell #2):

```powershell
# Poll health (PowerShell's Invoke-RestMethod works like curl)
Invoke-RestMethod -Uri http://localhost:9001/health
```

3) When `{'status':'ok'}` is returned, run the Java `MainCLI` to process a PCAP and post flows to the adapter (shell #2):

```powershell
# From repository root, run MainCLI against a pcap file and point it to the adapter endpoint
Set-Location -LiteralPath 'C:\Users\Sadhy Dashora\Downloads\cicflowmeter-4_upgrade\cicflowmeter-4_upgrade\CICFlowMeter-4.0'
java -cp 'bin_compiled;lib/*' MainCLI pcap\testpcap.pcap output\testpcap.pcap_Flow.csv http://localhost:9001/receive_log
```

Notes and troubleshooting:
- Start the Python adapter before starting `MainCLI` to avoid early "Connection refused" errors.
- If you see malformed or shifted fields in forwarded payloads, inspect `last_bad_rows.log` and `last_sent_payload.json` in the repository root to debug parsing issues.
- To test live capture instead of a PCAP, use the existing GUI or `cfm.bat`/`cfm` scripts and set the webhook URL to `http://<adapter-host>:<PORT>/receive_log`.
- To run the adapter in the background on Windows, use `Start-Process -NoNewWindow -FilePath python -ArgumentList '.\\log_adapter.py'` or run it inside a terminal multiplexer.
