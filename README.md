# CICFlowMeter Usage Guide

This guide provides step-by-step instructions aimed at beginners to quickly install and use
the CICFlowMeter wrapper and adapter to forward flows to a webhook or model endpoint.
Follow the Quickstart below for a working setup on Linux or Windows.

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

## Contact

Contact us at A.Habibi.L@unb.ca if there are any problems.

## Single-Command Wrapper (Adapter + CICFlowMeter)

A convenience wrapper `cicflowmeter` and Windows launcher `run_cicflowmeter.bat` are provided to start the Python adapter (`log_adapter.py`), capture (optional), run the Java `MainCLI`, and forward flow payloads to a model/webhook in one command.

Notes:
- The wrapper requires `python`, `java`, and optionally `tshark` (for live captures) available in your PATH.
- On Windows, `tshark` comes with the Wireshark installer (ensure "Install TShark" and "Install Npcap" are selected). If Wireshark is installed under `C:\Program Files\Wireshark`, the wrapper will work after adding that folder to your PATH.
- For live capture on Windows, `tshark -D` lists available interfaces and their numeric index. Use the index (e.g. `5`) as the `-i` argument.


**Quickstart (Beginner-friendly)**

- **Goal:** Run the adapter and process a PCAP or live interface so flows are forwarded
  to a webhook (or model endpoint) as JSON payloads.

- **What we'll set up:**
  - `log_adapter.py` — Flask adapter that receives CICFlowMeter posts and forwards
    batched JSON to your `MODEL_URL`.
  - `cicflowmeter` — convenience wrapper to start the adapter and run CICFlowMeter (or
    capture with `tshark`) in one command.

Step 0 — Clone / open repo

```powershell
cd "C:\Users\<you>\Downloads\cicflowmeter-4_upgrade\cicflowmeter-4_upgrade"
```

Step 1 — Install prerequisites

- Linux (Ubuntu/Debian example):

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip default-jre
```

- Windows:

- Install Python 3.x from https://www.python.org and ensure `python` is on your PATH.
- Install Java (JRE/JDK 11+ recommended) and ensure `java` is on your PATH.
- (Optional for live capture) Install Wireshark and choose the options to install
  `tshark` and `Npcap`. Default install path is `C:\Program Files\Wireshark`.

Step 2 — Create Python virtual environment and install adapter deps

```bash
python -m venv .venv
# activate the venv
# Linux: source .venv/bin/activate
# Windows (PowerShell): .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Step 3 — Quick smoke test: show wrapper help

```bash
python cicflowmeter -h
```

Step 4 — Run a simple PCAP test (process one file and forward up to 10 flows)

```powershell
# Windows - run from project root
.\run_cicflowmeter.bat -p "CICFlowMeter-4.0\pcap\testpcap.pcap" -u "https://webhook.site/YOUR_WEBHOOK" -limit 10
```

Step 5 — Live capture test (requires `tshark`)

```powershell
# List interfaces (Windows):
tshark -D
# If the Wi‑Fi adapter is index 5, capture 1-second slices and forward 10 flows total
.\run_cicflowmeter.bat -i 5 -u "https://webhook.site/YOUR_WEBHOOK" -limit 10 -t 1
```

Step 6 — Including `resource_id` and `include_confidence`

If you want the adapter to tag forwarded payloads with a particular resource and ask
the model to include a confidence value, pass `--resource-id` and `--include-confidence`:

```powershell
.\run_cicflowmeter.bat -p "CICFlowMeter-4.0\pcap\testpcap.pcap" -u "https://webhook.site/YOUR_WEBHOOK" -limit 10 --resource-id demo-resource-0001 --include-confidence
```

The adapter will send JSON like:

```json
{
  "client_id": "demo-client-0001",
  "flows": [ /* ... flow objects ... */ ],
  "include_confidence": true,
  "resource_id": "demo-resource-0001"
}
```

Troubleshooting quick tips:

- If `tshark` is not found on Windows: add `C:\Program Files\Wireshark` to your PATH or reinstall Wireshark ensuring TShark is selected.
- If you see no flows forwarded: check `last_sent_payload.json` for the last payload and `last_bad_rows.log` for parse errors.
- If the adapter is not receiving logs from `MainCLI`, ensure the wrapper displayed `Adapter health OK` before `MainCLI` starts.

Advanced: If you want the adapter to keep running beyond a test limit, omit `-limit`.

Example: start adapter only (for debugging) and POST a sample CSV line to it:

```bash
# start adapter in a separate terminal
python log_adapter.py
# then POST a test CSV row (replace with a real CSV row matching CSV_HEADER)
curl -XPOST -H "Content-Type: application/json" -d '{"log":"FLOW_ID,..."}' http://127.0.0.1:9001/receive_log
```

To include a `resource_id` and request that the adapter include a top-level
`include_confidence` flag in the forwarded payload, add the `--resource-id`
and `--include-confidence` flags. Example:

```powershell
.\run_cicflowmeter.bat -p "CICFlowMeter-4.0\pcap\testpcap.pcap" -u "https://webhook.site/YOUR_WEBHOOK" -limit 10 --resource-id demo-resource-0001 --include-confidence
```

The forwarded JSON will include `resource_id` and (when `--include-confidence` is set)
`include_confidence: true` at the top level, for example:

```json
{
  "client_id": "demo-client-0001",
  "flows": [ ... ],
  "include_confidence": true,
  "resource_id": "demo-resource-0001"
}
```

Behavior details:
- The wrapper starts the adapter (which listens on `http://127.0.0.1:9001/receive_log`) and waits for `/health` before running `MainCLI`.
- The adapter will stop (exit) automatically when it has forwarded `MAX_SEND` flows (set via `-limit`).
- When `-limit` is set, the wrapper now terminates the running `MainCLI` process when the adapter exits to avoid further POST attempts (prevents noisy "Connection refused" messages).

Troubleshooting:
- If you see `tshark not found in PATH`, either install Wireshark (include TShark/Npcap) or add the folder containing `tshark.exe` to your PATH.
- To list interfaces for the correct index on Windows:
```powershell
tshark -D
```

