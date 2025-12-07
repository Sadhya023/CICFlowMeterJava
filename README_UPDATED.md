# CICFlowMeter Usage Guide

This guide provides instructions on how to set up, run, and utilize the CICFlowMeter tool for network traffic analysis and webhook integration.

## Introduction

The CICFlowMeter is an open-source tool designed to generate Biflows from PCAP files and extract various features from these flows. It supports bidirectional flow generation, allowing for statistical time-related features to be calculated for both forward and backward directions. Key functionalities include feature selection, adding new features, and controlling flow timeout durations.

For more details and citations, refer to the published papers:
- Gerard Drapper Gil, Arash Habibi Lashkari, Mohammad Mamun, Ali A. Ghorbani, "Characterization of Encrypted and VPN Traffic Using Time-Related Features", In Proceedings of the 2nd International Conference on Information Systems Security and Privacy(ICISSP 2016) , pages 407-414, Rome , Italy
- Arash Habibi Lashkari, Gerard Draper-Gil, Mohammad Saiful Islam Mamun and Ali A. Ghorbani, "Characterization of Tor Traffic Using Time Based Features", In the proceeding of the 3rd International Conference on Information System Security and Privacy, SCITEPRESS, Porto, Portugal, 2017

## Prerequisites

The only prerequisite is the `libpcap` library (or WinPcap on Windows systems) to be pre-installed.

### For Linux

```bash
sudo apt-get install libpcap-dev
```

### For Windows

Download [WinPcap](https://www.winpcap.org/install/default.htm).

### Java Runtime Environment

CICFlowMeter requires Java 8 or newer (Java 11 LTS is recommended). The `cfm` launcher script will attempt to use the `java` command found in your system's PATH or the one specified by the `JAVA_HOME` environment variable.

- **Check installed Java:**
  ```bash
  java -version
  ```
- **Force a specific Java for one run:**
  ```bash
  JAVA_HOME=/path/to/your/java/jdk ./CICFlowMeter-4.0/bin/cfm "inputFolder" "outputFolder"
  ```
  (Replace `/path/to/your/java/jdk` with the actual path to your Java installation.)

## Execution

Navigate to the `CICFlowMeter-4.0` directory within your project.

### For Linux

Open a terminal in the project root (`/home/ashish/Code/Java/cicflowmeter-4_upgrade/`).

- **For GUI:**
  ```bash
  sudo ./CICFlowMeter-4.0/bin/CICFlowMeter
  ```
- **For Command Line (Offline Mode):**
  ```bash
  ./CICFlowMeter-4.0/bin/cfm "inputFolder" "outputFolder"
  ```

### For Windows

Launch the Command Prompt and run these commands from the `CICFlowMeter-4.0` directory.

- **For GUI:**
  ```bash
  CICFlowMeter.bat
  ```
- **For Command Line (Offline Mode):**
  ```bash
  cfm.bat "inputFolder" "outputFolder"
  ```

## Input Folder

For offline processing, the `inputFolder` should contain your PCAP files.

- **Supported extensions:** `*.pcap`, `*.pcapng`.
- **File format:** Files must be plain libpcap captures (uncompressed).
- **Permissions:** Ensure the user running `cfm` has read permissions on the input folder and its contents.
- **Path with spaces:** If your input folder path contains spaces, enclose it in quotes (e.g., `"./path to my pcaps"`).
- **Single file processing:** You can point the `inputFolder` to a directory containing a single PCAP file.

**Example Command:**
```bash
./CICFlowMeter-4.0/bin/cfm "/home/ashish/Code/Java/cicflowmeter-4_upgrade/CICFlowMeter-4.0/pcap" "/home/ashish/Code/Java/cicflowmeter-4_upgrade/CICFlowMeter-4.0/output"
```

## Sending Logs to a Webhook

To send network flow logs to a webhook URL, use the following command:

```bash
env WEBHOOK_URL="https://webhook.site/YOUR_WEBHOOK_URL" ./CICFlowMeter-4.0/bin/cfm "./CICFlowMeter-4.0/pcap" "./CICFlowMeter-4.0/output"
```

**How it works:**
- `WEBHOOK_URL`: Set this environment variable to your webhook endpoint. The tool will POST logs to this URL as it processes flows.
- First argument (`./CICFlowMeter-4.0/pcap`): Path to the folder containing your PCAP files.
- Second argument (`./CICFlowMeter-4.0/output`): Path to the folder where output CSV files will be saved.

**What to expect:**
- The tool will process all PCAP files in the input folder.
- Logs (including start, finish, and flow logs) will be sent to your webhook in real time.
- Output CSV files will be generated in the output folder.

**Troubleshooting:**
- If you do not see logs at your webhook, check that the `WEBHOOK_URL` is correct and reachable from your machine.
- Ensure the `cfm` script has execute permissions (`chmod +x ./CICFlowMeter-4.0/bin/cfm`).
- Make sure your Java version is compatible (Java 8 or newer).
- If you see only start/finish logs but not flow logs, verify that your PCAP files contain valid network traffic and that the tool is not exiting early.

**Example:**
```bash
env WEBHOOK_URL="https://webhook.site/977e5fa2-20e0-4fdb-8b5c-d21a9ad7ac5e" ./CICFlowMeter-4.0/bin/cfm "./CICFlowMeter-4.0/pcap" "./CICFlowMeter-4.0/output"
```

## Get Started

### Offline Mode

1.  **Select Input Folder:** Choose the folder containing your PCAP files.
2.  **Select Output Folder:** Choose the folder where you want to save the generated CSV files.
3.  **Click OK.**

### Realtime Mode

1.  **Click Load button:** To find a list of available network interfaces.
2.  **Select Interface:** Choose the network interface you wish to monitor.
3.  **Click Start button:** Begin the capture process.
4.  **Click Stop button:** Stop the process and save the CSV output in the application folder's `data/daily` subdirectory.

## Troubleshooting

-   **`Permission denied` error:** Ensure the `cfm` script has execute permissions.
    ```bash
    chmod +x ./CICFlowMeter-4.0/bin/cfm
    ```
-   **`UnsatisfiedLinkError`:** This usually indicates that the native `jnetpcap` libraries (`libjnetpcap.so` on Linux, `jnetpcap.dll` on Windows) cannot be found or loaded by the Java Virtual Machine. The `cfm` script is configured to set `java.library.path` to the correct native library directory (`CICFlowMeter-4.0/lib/native`). If you encounter this error, ensure your Java installation is compatible with the provided native libraries (e.g., 64-bit Java for 64-bit native libraries).

## Python Adapter (CLI) Integration

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

## One-command wrapper: `cicflowmeter`

A convenience wrapper `cicflowmeter` is included to start the Python adapter and invoke CICFlowMeter from a single command. It orchestrates the adapter (`log_adapter.py`) and the Java `MainCLI` so you can run live capture or process a PCAP and forward batched JSON payloads to a webhook or model endpoint.

Usage examples (PowerShell):

```powershell
# Process a single pcap and forward to your webhook (adapter will forward batches):
./cicflowmeter -p pcap\testpcap.pcap -u http://localhost:9001/receive_log -limit 10 -t 1

# Capture from interface eth2 in 1-second slices, forward to webhook, stop after 10 forwarded flows:
./cicflowmeter -i eth2 -u "https://webhook.site/68560c50-0f72-4a51-942f-984216e99aa9" -limit 10 -t 1
```

Command-line flags:
- `-i, --iface` : network interface for live capture (requires `tshark` in PATH).
- `-p, --pcap`  : PCAP file to process instead of live capture.
- `-u, --url`   : destination model/webhook URL (adapter forwards to this URL).
- `-limit`      : total number of flows to forward (adapter `MAX_SEND`).
- `-t, --time`  : capture slice duration (seconds) for live mode, and adapter flush timeout.

Notes:
- The wrapper starts `log_adapter.py` (the adapter listens on `http://127.0.0.1:9001/receive_log`) and points `MainCLI` at the adapter so flows are forwarded as JSON `{client_id, flows: [...]}`.
- Set `-limit` to a small number (e.g., 10) during tests — the adapter will exit after forwarding that many flows.
- For live capture the wrapper uses `tshark` to create small pcap slices and then invokes the Java `MainCLI` on each slice. Install Wireshark/tshark to enable this mode.

## Contact

Contact us at A.Habibi.L@unb.ca if there are any problems.
