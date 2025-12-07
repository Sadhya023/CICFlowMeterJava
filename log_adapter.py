#!/usr/bin/env python3
"""
Simple adapter to receive CICFlowMeter log posts (JSON or raw CSV lines),
convert them into the model input schema {client_id, flows: [...]}, batch them,
and forward to a model endpoint.

Usage:
  python log_adapter.py

Environment variables:
  MODEL_URL - full URL to forward batched payloads (default http://localhost:9001/predict/buffered)
  CLIENT_ID - client identifier to include in payloads (default demo-client-0001)
  PORT      - port to listen on (default 9001)

The adapter accepts POSTs at /receive_log. The sender (MainCLI) posts JSON like {"log": "..."}.
If the log contains a CSV row, the adapter will parse it using CSV_HEADER and convert types.

Adjust CSV_HEADER to match your CICFlowMeter CSV column order and the fields your model expects.
"""

from flask import Flask, request, jsonify
import csv
import io
import threading
import time
import requests
import os
import logging
import json
import re

# Configuration
MODEL_URL = os.environ.get('MODEL_URL', 'https://webhook.site/68560c50-0f72-4a51-942f-984216e99aa9')
CLIENT_ID = os.environ.get('CLIENT_ID', 'demo-client-0001')
PORT = int(os.environ.get('PORT', '9001'))
# Default to batch size 10 for this test
BATCH_SIZE = int(os.environ.get('BATCH_SIZE', '10'))
BATCH_TIMEOUT = float(os.environ.get('BATCH_TIMEOUT', '2.0'))

# Optional: limit total forwarded flows (set to 10 for the user's request)
MAX_SEND = os.environ.get('MAX_SEND')
if MAX_SEND is not None:
    try:
        MAX_SEND = int(MAX_SEND)
    except Exception:
        MAX_SEND = None

# Counter of total forwarded flows
_total_sent = 0

# Optional resource identifier (if a client owns multiple resources)
RESOURCE_ID = os.environ.get('RESOURCE_ID')
# Include a top-level include_confidence flag in forwarded payloads when set to true
INCLUDE_CONFIDENCE = os.environ.get('INCLUDE_CONFIDENCE', 'false').lower() in ('1', 'true', 'yes')

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

app = Flask(__name__)

def _normalize_header(name: str) -> str:
    """Normalize a CSV header name into snake_case-like identifier."""
    s = name.strip()
    s = s.replace('%', 'pct')
    s = s.replace('/', '_')
    s = s.replace('-', '_')
    s = s.replace('(', '')
    s = s.replace(')', '')
    s = s.replace('.', '')
    s = s.replace('  ', ' ')
    s = s.replace(' ', '_')
    return s.lower()

# Default CSV header placeholder. If a sample CICFlowMeter CSV exists in the repository
# we will attempt to read and normalize its header so incoming rows are mapped correctly.
CSV_HEADER = []

def _detect_csv_header_from_repo():
    # Look for a likely output CSV produced by CICFlowMeter
    possible = [
        'CICFlowMeter-4.0/output/*_Flow.csv',
        'CICFlowMeter-4.0/output/*.csv',
        'CICFlowMeter-4.0/output/testpcap.pcap_Flow.csv',
        'CICFlowMeter-4.0/output/testpcap_Flow.csv',
        'output/*_Flow.csv',
        'output/*.csv',
        'CICFlowMeter-4.0/bin/data/daily/*_Flow.csv',
        'CICFlowMeter-4.0/bin/data/daily/*.csv',
    ]
    for p in possible:
        try:
            # allow glob-like pattern
            import glob as _glob
            matches = _glob.glob(p)
            if not matches:
                continue
            # prefer the most recent match
            matches = sorted(matches)
            for candidate in matches:
                if os.path.exists(candidate):
                    with open(candidate, 'r', encoding='utf-8', errors='ignore') as fh:
                        # use csv.reader to correctly parse header even if it contains commas
                        try:
                            rdr = csv.reader(fh)
                            header = next(rdr)
                        except Exception:
                            # fallback to naive split
                            fh.seek(0)
                            first = fh.readline().strip()
                            if not first:
                                continue
                            header = [c.strip() for c in first.split(',')]
                        if not header:
                            continue
                        return [_normalize_header(c) for c in header]
        except Exception:
            continue
    return None


# Try to auto-detect CSV header from the workspace.
detected = _detect_csv_header_from_repo()
if detected:
    CSV_HEADER = detected
    logging.info('Auto-detected CSV header with %d columns', len(CSV_HEADER))
    logging.debug('CSV_HEADER: %s', CSV_HEADER)
else:
    # Fallback to the full CICFlowMeter header (normalized) — matches observed `*_Flow.csv` files.
    CSV_HEADER = [
        _normalize_header(h) for h in [
            'Flow ID','Src IP','Src Port','Dst IP','Dst Port','Protocol','Timestamp','Flow Duration',
            'Tot Fwd Pkts','Tot Bwd Pkts','TotLen Fwd Pkts','TotLen Bwd Pkts','Fwd Pkt Len Max','Fwd Pkt Len Min',
            'Fwd Pkt Len Mean','Fwd Pkt Len Std','Bwd Pkt Len Max','Bwd Pkt Len Min','Bwd Pkt Len Mean','Bwd Pkt Len Std',
            'Flow Byts/s','Flow Pkts/s','Flow IAT Mean','Flow IAT Std','Flow IAT Max','Flow IAT Min','Fwd IAT Tot',
            'Fwd IAT Mean','Fwd IAT Std','Fwd IAT Max','Fwd IAT Min','Bwd IAT Tot','Bwd IAT Mean','Bwd IAT Std',
            'Bwd IAT Max','Bwd IAT Min','Fwd PSH Flags','Bwd PSH Flags','Fwd URG Flags','Bwd URG Flags','Fwd Header Len',
            'Bwd Header Len','Fwd Pkts/s','Bwd Pkts/s','Pkt Len Min','Pkt Len Max','Pkt Len Mean','Pkt Len Std','Pkt Len Var',
            'FIN Flag Cnt','SYN Flag Cnt','RST Flag Cnt','PSH Flag Cnt','ACK Flag Cnt','URG Flag Cnt','CWE Flag Count',
            'ECE Flag Cnt','Down/Up Ratio','Pkt Size Avg','Fwd Seg Size Avg','Bwd Seg Size Avg','Fwd Byts/b Avg',
            'Fwd Pkts/b Avg','Fwd Blk Rate Avg','Bwd Byts/b Avg','Bwd Pkts/b Avg','Bwd Blk Rate Avg','Subflow Fwd Pkts',
            'Subflow Fwd Byts','Subflow Bwd Pkts','Subflow Bwd Byts','Init Fwd Win Byts','Init Bwd Win Byts','Fwd Act Data Pkts',
            'Fwd Seg Size Min','Active Mean','Active Std','Active Max','Active Min','Idle Mean','Idle Std','Idle Max','Idle Min','Label'
        ]
    ]
    logging.info('Using fallback CSV_HEADER with %d columns', len(CSV_HEADER))

buffer = []
buffer_lock = threading.Lock()
last_flush = time.time()


def try_parse_row_to_flow(row):
    """Convert a CSV row (list of strings) to a typed flow dict based on CSV_HEADER."""
    flow = {}
    # Map by index so mis-sized rows don't shift field names unpredictably.
    for idx, raw in enumerate(row):
        key = CSV_HEADER[idx] if idx < len(CSV_HEADER) else f'col_{idx}'
        v = raw
        if v is None:
            flow[key] = None
            continue
        v = v.strip()
        if v == '':
            flow[key] = None
            continue
        lk = key.lower()
        # Preserve obvious string fields
        if 'ip' in lk or 'timestamp' in lk or 'time' in lk or 'flow_id' in lk or 'label' in lk:
            flow[key] = v
            continue
        # Normalize special tokens
        if v.lower() in ('infinity', 'inf', 'nan'):
            flow[key] = None
            continue
        # Try integer then float
        try:
            if v.isdigit() or (v.startswith('-') and v[1:].isdigit()):
                flow[key] = int(v)
                continue
            fv = float(v)
            if fv.is_integer():
                flow[key] = int(fv)
            else:
                flow[key] = fv
            continue
        except Exception:
            # As a final heuristic: sometimes numeric fields contain commas or locale
            try:
                nv = v.replace(',', '')
                fv = float(nv)
                if fv.is_integer():
                    flow[key] = int(fv)
                else:
                    flow[key] = fv
                continue
            except Exception:
                flow[key] = v
    return flow


def flush_buffer():
    global buffer, last_flush, _total_sent
    with buffer_lock:
        if not buffer:
            return
        # Build an ordered set of flows guaranteeing canonical ordering
        ordered_flows = []
        for f in buffer:
            ordered = {}
            for key in CSV_HEADER:
                ordered[key] = f.get(key, None)
            # append any extra columns after canonical ones
            for extra in sorted([k for k in f.keys() if k not in CSV_HEADER]):
                ordered[extra] = f[extra]
            ordered_flows.append(ordered)

        # If MAX_SEND is set, enforce total-send limit
        if MAX_SEND is not None:
            remaining_allowed = max(0, MAX_SEND - _total_sent)
            if remaining_allowed <= 0:
                logging.info('Max total sends reached (%d). Not forwarding.', MAX_SEND)
                buffer = []
                logging.info('Adapter exiting after reaching MAX_SEND=%d', MAX_SEND)
                try:
                    os._exit(0)
                except Exception:
                    pass
                return
            if len(ordered_flows) > remaining_allowed:
                ordered_flows = ordered_flows[:remaining_allowed]

        payload = {'client_id': CLIENT_ID, 'flows': ordered_flows}
        # Optionally include a top-level include_confidence flag
        if INCLUDE_CONFIDENCE:
            payload['include_confidence'] = True
        # Optionally include a resource identifier so the model knows which
        # resource (when a client has multiple resources) this batch belongs to.
        if RESOURCE_ID:
            payload['resource_id'] = RESOURCE_ID
        # clear buffer (we forward all selected items)
        buffer = []

    try:
        logging.info('Forwarding %d flows to %s', len(payload['flows']), MODEL_URL)
        if payload['flows']:
            logging.info('Preview first flow keys: %s', list(payload['flows'][0].keys())[:12])
        # Persist a copy of the payload for inspection (non-blocking)
        try:
            tmp = 'last_sent_payload.tmp.json'
            with open(tmp, 'w', encoding='utf-8') as fh:
                json.dump(payload, fh, default=str, indent=None)
            os.replace(tmp, 'last_sent_payload.json')
        except Exception:
            logging.debug('Could not write last_sent_payload.json')
        r = requests.post(MODEL_URL, json=payload, timeout=10)
        logging.info('Model response: %s %s', r.status_code, (r.text[:500] if r.text else ''))
        # update sent counter
        _total_sent += len(payload['flows'])
        logging.info('Total flows forwarded so far: %d', _total_sent)
        # shutdown if we've reached MAX_SEND
        if MAX_SEND is not None and _total_sent >= MAX_SEND:
            logging.info('Reached MAX_SEND=%d, shutting down adapter.', MAX_SEND)
            try:
                os._exit(0)
            except Exception:
                pass
    except Exception as e:
        logging.exception('Failed to forward to model: %s', e)
    last_flush = time.time()


def background_flusher():
    global last_flush
    while True:
        time.sleep(0.5)
        with buffer_lock:
            should_flush = bool(buffer) and (len(buffer) >= BATCH_SIZE or (time.time() - last_flush) >= BATCH_TIMEOUT)
        if should_flush:
            flush_buffer()


# Start flusher thread
flusher = threading.Thread(target=background_flusher, daemon=True)
flusher.start()


@app.route('/receive_log', methods=['POST'])
def receive_log():
    """Endpoint to receive logs from MainCLI or other senders.
    Accepts JSON like {"log": "..."} or raw text/plain body containing a CSV row.
    """
    s = None
    stream = None
    if request.is_json:
        j = request.get_json(silent=True)
        if j:
            # prefer structured posts from MainCLI which include 'stream' and 'log'
            stream = j.get('stream')
            s = j.get('log') or j.get('message') or None
    if s is None:
        s = request.get_data(as_text=True).strip()
    if not s:
        return jsonify({'status':'no data'}), 400

    # If the sender indicated this line is already a FLOW row, avoid prefix stripping
    if stream and str(stream).upper() == 'FLOW':
        candidate = s
    else:
        # Some senders prefix lines like "FLOW: <csv>" or "STDOUT: <csv>" - prefer to
        # find a CSV-looking substring. Only strip a leading prefix when doing so
        # yields something that still looks like CSV.
        candidate = s
        if ':' in s and s.count(',') >= 2:
            after = s.split(':', 1)[1].strip()
            if after.count(',') >= 2:
                candidate = after

    # Attempt to robustly extract a CSV-looking substring. Some senders prefix
    # logs (e.g. "[FLOW] ...") or include other text; find the first location
    # that looks like a Flow ID (IP-IP-...-port-port-proto) and parse from there.
    def _find_csv_start(s: str):
        # Matches patterns like 10.1.2.3-8.8.8.8-1234-80-6 (flow id at start)
        m = re.search(r"\d{1,3}(?:\.\d{1,3}){3}-\d{1,3}(?:\.\d{1,3}){3}-\d+-\d+-\d+", s)
        return m.start() if m else None

    # quick check for CSV structure: if no comma present anywhere, ignore early
    if ',' not in candidate:
        logging.info('Received non-CSV log (ignored): %s', candidate[:200])
        return jsonify({'status':'ignored_non_csv'}), 200

    # If candidate looks too short relative to expected header columns, try to
    # find a CSV start inside the string (handles prefixed text or mixed output).
    try:
        # If the candidate doesn't have at least header-1 commas, try to locate
        # the real CSV start and re-slice.
        expected_commas = max(0, len(CSV_HEADER) - 1)
        if expected_commas > 0 and candidate.count(',') < min(3, expected_commas):
            start = _find_csv_start(candidate)
            if start is not None:
                logging.debug('Detected CSV start at pos %d; trimming prefix', start)
                candidate = candidate[start:]

        rdr = csv.reader(io.StringIO(candidate))
        row = next(rdr)
    except Exception as e:
        logging.exception('CSV parse failed: %s -- candidate preview: %s', e, candidate[:200])
        try:
            with open('last_bad_rows.log', 'a', encoding='utf-8') as fh:
                fh.write(json.dumps({'stream': stream, 'raw': candidate, 'error': str(e)}) + "\n")
        except Exception:
            logging.debug('Could not write last_bad_rows.log')
        return jsonify({'status':'csv_parse_failed'}), 200

    # If header row is sent, detect and set CSV_HEADER dynamically
    # e.g., lines starting with 'Flow ID' or 'Src IP'
    header_tokens = set([_normalize_header(x) for x in row if x and any(ch.isalpha() for ch in x)])
    known_headers = {'flow_id', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'timestamp', 'flow_duration', 'tot_fwd_pkts'}
    if header_tokens & known_headers:
        # set CSV_HEADER to normalized header names from this row
        new_header = [_normalize_header(x) for x in row]
        # update global CSV_HEADER
        CSV_HEADER.clear()
        CSV_HEADER.extend(new_header)
        logging.info('Received header row; updated CSV_HEADER with %d columns', len(CSV_HEADER))
        logging.debug('CSV_HEADER: %s', CSV_HEADER)
        return jsonify({'status':'header_ignored','detected_columns':len(CSV_HEADER)}), 200

    # Validate row length matches detected CSV_HEADER to avoid shifted/misaligned mappings.
    if len(row) != len(CSV_HEADER):
        logging.warning('CSV row length %d != header length %d - treating as malformed', len(row), len(CSV_HEADER))
        # As a last attempt, try finding a CSV-like substring by locating the
        # first comma-separated segment that gives the expected column count.
        if ',' in candidate and len(CSV_HEADER) > 3:
            parts = candidate.split(',')
            # slide window over parts to find contiguous segment matching header len
            for i in range(0, max(1, len(parts) - len(CSV_HEADER) + 1)):
                seg = ','.join(parts[i:i + len(CSV_HEADER)])
                try:
                    rdr = csv.reader(io.StringIO(seg))
                    r2 = next(rdr)
                    if len(r2) == len(CSV_HEADER):
                        logging.info('Recovered CSV segment starting at part %d', i)
                        row = r2
                        break
                except Exception:
                    continue

        # If still mismatched, persist and skip
        if len(row) != len(CSV_HEADER):
            try:
                with open('last_bad_rows.log', 'a', encoding='utf-8') as fh:
                    fh.write(json.dumps({'stream': stream, 'raw': candidate, 'len': len(row), 'expected': len(CSV_HEADER)}) + "\n")
            except Exception:
                logging.debug('Could not write last_bad_rows.log')
            return jsonify({'status':'malformed_row','got':len(row),'expected':len(CSV_HEADER)}), 200

    flow = try_parse_row_to_flow(row)
    with buffer_lock:
        buffer.append(flow)
        buf_len = len(buffer)
    logging.info('Accepted flow, buffer size=%d', buf_len)
    if buf_len >= BATCH_SIZE:
        # flush asynchronously
        threading.Thread(target=flush_buffer, daemon=True).start()
    return jsonify({'status':'accepted','buffer':buf_len}), 200


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status':'ok','buffer':len(buffer)}), 200


if __name__ == '__main__':
    logging.info('Adapter listening on http://0.0.0.0:%d/receive_log -> forwarding to %s', PORT, MODEL_URL)
    app.run(host='0.0.0.0', port=PORT)
