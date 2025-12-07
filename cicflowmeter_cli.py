#!/usr/bin/env python3
"""
Lightweight CLI wrapper for CICFlowMeter with a friendly interface.

Usage example (see --help):
  python cicflowmeter_cli.py -f CICFlowMeter-4.0/pcap/testpcap.pcap -c output.csv

This script will:
- compile `MainCLI.java` if needed (into `CICFlowMeter-4.0/bin_compiled`)
- invoke `MainCLI` for the requested pcap(s)
- support output as CSV or URL mode (when using URL mode, the wrapper still writes a temporary CSV that is posted by MainCLI)
- support filtering output fields and merging directory outputs

Note: This wrapper assumes a Java runtime is available on PATH. It runs on Windows (PowerShell) and POSIX shells.
"""
import argparse
import subprocess
import sys
import os
from pathlib import Path
import tempfile
import shutil
import glob
import csv
import logging


def ensure_compiled(cic_dir: Path, src_dir: Path):
    """Ensure MainCLI.class exists in a bin_compiled directory. Compile if missing."""
    bin_dir = cic_dir / 'bin_compiled'
    classfile = bin_dir / 'MainCLI.class'
    if classfile.exists():
        logging.debug('Found compiled MainCLI at %s', classfile)
        return bin_dir

    # Create bin_compiled and run javac
    logging.info('Compiling MainCLI.java into %s', bin_dir)
    bin_dir.mkdir(parents=True, exist_ok=True)
    java_files = list(src_dir.glob('*.java'))
    if not java_files:
        raise FileNotFoundError('No Java sources found in ' + str(src_dir))
    javac_cmd = ['javac', '-d', str(bin_dir)] + [str(p) for p in java_files]
    logging.debug('Running: %s', ' '.join(javac_cmd))
    res = subprocess.run(javac_cmd, cwd=str(cic_dir), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        logging.error('javac failed:\n%s\n%s', res.stdout, res.stderr)
        raise RuntimeError('javac failed')
    logging.info('Compilation finished')
    return bin_dir


def run_maincli(cic_dir: Path, bin_dir: Path, pcap: Path, output_csv: Path, log_url: str, verbose=False):
    # Build classpath: include lib/* and compiled classes dir
    lib_pattern = str(cic_dir / 'lib' / '*')
    classpath = f"{lib_pattern}{os.pathsep}{str(bin_dir)}"
    cmd = ['java', '-cp', classpath, 'MainCLI', str(pcap), str(output_csv), log_url]
    logging.info('Running CICFlowMeter on %s -> %s (log_url=%s)', pcap, output_csv, log_url)
    if verbose:
        print(' '.join(cmd))
    proc = subprocess.Popen(cmd, cwd=str(cic_dir), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = proc.communicate()
    if out:
        print(out)
    if err:
        print(err, file=sys.stderr)
    return proc.returncode


def filter_csv_fields(src_csv: Path, dst_csv: Path, fields):
    with src_csv.open('r', newline='', encoding='utf-8') as inf, dst_csv.open('w', newline='', encoding='utf-8') as outf:
        rdr = csv.DictReader(inf)
        # if requested fields missing, raise
        missing = [f for f in fields if f not in rdr.fieldnames]
        if missing:
            raise ValueError(f'Requested fields not present in CSV: {missing}')
        w = csv.DictWriter(outf, fieldnames=fields)
        w.writeheader()
        for row in rdr:
            out = {k: row.get(k, '') for k in fields}
            w.writerow(out)


def merge_csvs(csv_paths, out_path: Path):
    first = True
    with out_path.open('w', newline='', encoding='utf-8') as outf:
        writer = None
        for p in csv_paths:
            with p.open('r', newline='', encoding='utf-8') as inf:
                rdr = csv.reader(inf)
                header = next(rdr)
                if first:
                    writer = csv.writer(outf)
                    writer.writerow(header)
                    first = False
                for row in rdr:
                    writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(prog='cicflowmeter', description='Wrapper CLI for CICFlowMeter')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--interface', dest='interface', help='Live capture interface name (e.g. eth0, wlan0)')
    group.add_argument('-f', '--file', dest='file')
    group.add_argument('-d', '--directory', dest='directory')
    outgroup = parser.add_mutually_exclusive_group(required=True)
    outgroup.add_argument('-c', '--csv', action='store_true')
    outgroup.add_argument('-u', '--url', action='store_true')
    parser.add_argument('--fields', help='comma separated fields to include in output (default: all)')
    parser.add_argument('--merge', action='store_true', help='merge all pcap files into a single CSV (only with -d)')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--duration', type=int, default=30, help='Duration (seconds) for live capture when using -i interface (default: 30)')
    parser.add_argument('--no-csv', action='store_true', help='Do not keep CSV output files (useful for URL-only mode)')
    parser.add_argument('output', help='output file (csv) or url (url mode)')

    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

    repo_root = Path('.').resolve()
    cic_dir = repo_root / 'CICFlowMeter-4.0'
    if not cic_dir.exists():
        logging.error('CICFlowMeter-4.0 directory not found in %s', repo_root)
        sys.exit(2)

    src_dir = cic_dir / 'src'
    try:
        bin_dir = ensure_compiled(cic_dir, src_dir)
    except Exception as e:
        logging.error('Failed to compile MainCLI: %s', e)
        sys.exit(3)

    fields = [f.strip() for f in args.fields.split(',')] if args.fields else None

    # Determine mode and inputs
    pcaps = []
    if args.file:
        pcaps = [Path(args.file)]
    elif args.interface:
        # Live capture requested. Prefer streaming capture directly into a FIFO (POSIX) so MainCLI can read
        # from the "file" path without leaving a persistent pcap on disk. On Windows we fall back to a
        # temporary pcap file because named FIFOs are not portable in the same way.
        logging.info('Interface capture selected: %s (duration=%ss).', args.interface, args.duration)
        duration = args.duration

        def _find_exe(names):
            for n in names:
                p = shutil.which(n)
                if p:
                    return p
            return None

        capturer = _find_exe(['dumpcap', 'tshark', 'tcpdump'])
        if not capturer:
            logging.error('No capture tool found (dumpcap/tshark/tcpdump). Install Wireshark (dumpcap) or tshark, or tcpdump.')
            sys.exit(5)

        # On POSIX we can create a FIFO and stream pcap bytes into it; MainCLI will open and read it like a file.
        use_fifo = os.name != 'nt'
        if use_fifo:
            fifo_dir = Path(tempfile.mkdtemp(prefix='cfm_fifo_'))
            fifo_path = fifo_dir / 'live_capture.pcap'
            try:
                os.mkfifo(str(fifo_path))
            except Exception as e:
                logging.warning('mkfifo failed (%s), falling back to temp pcap file: %s', e, e)
                use_fifo = False

        if not use_fifo:
            fd, tmp_pcap = tempfile.mkstemp(prefix='cfm_live_', suffix='.pcap')
            os.close(fd)
            tmp_path = Path(tmp_pcap)

        # Build capture command that writes to stdout (so we can pipe into FIFO or file)
        base = os.path.basename(capturer).lower()
        if base.startswith('dumpcap') or base.startswith('tshark'):
            cap_cmd = [capturer, '-i', args.interface, '-a', f'duration:{duration}', '-w', '-']
        else:
            # tcpdump: -w - write raw pcap to stdout; -U makes output unbuffered
            cap_cmd = [capturer, '-i', args.interface, '-w', '-', '-U', f'-G', str(duration)] if base.startswith('tcpdump') else [capturer, '-i', args.interface, '-w', '-']

        logging.info('Starting capture command: %s', ' '.join(cap_cmd))

        try:
            cap_proc = subprocess.Popen(cap_cmd, cwd=str(repo_root), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except Exception as e:
            logging.error('Failed to start capture command: %s', e)
            # cleanup
            if not use_fifo and 'tmp_path' in locals() and tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            if use_fifo and fifo_dir.exists():
                try:
                    fifo_path.unlink()
                except Exception:
                    pass
                shutil.rmtree(fifo_dir, ignore_errors=True)
            sys.exit(6)

        if use_fifo:
            # Stream capture stdout into the FIFO in a background thread.
            import threading

            def _stream_to_fifo(stdout_pipe, fifo_p):
                try:
                    with open(fifo_p, 'wb') as wf:
                        while True:
                            chunk = stdout_pipe.read(8192)
                            if not chunk:
                                break
                            wf.write(chunk)
                except Exception as ex:
                    logging.debug('FIFO writer exiting: %s', ex)

            streamer = threading.Thread(target=_stream_to_fifo, args=(cap_proc.stdout, str(fifo_path)), daemon=True)
            streamer.start()
            pcaps = [fifo_path]
            logging.info('Streaming capture into FIFO %s (MainCLI will read from it)', fifo_path)
        else:
            # Stream stdout into a temporary file (write as it arrives) so MainCLI can read it.
            # We'll write capture stdout into tmp_path in a background thread to avoid blocking.
            import threading

            def _stream_to_file(stdout_pipe, out_file):
                try:
                    with open(out_file, 'wb') as wf:
                        while True:
                            chunk = stdout_pipe.read(8192)
                            if not chunk:
                                break
                            wf.write(chunk)
                except Exception as ex:
                    logging.debug('File writer exiting: %s', ex)

            writer = threading.Thread(target=_stream_to_file, args=(cap_proc.stdout, str(tmp_path)), daemon=True)
            writer.start()
            pcaps = [tmp_path]
            logging.info('Streaming capture into temp pcap %s', tmp_path)

        # Note: we'll wait for the capture to finish implicitly by waiting for MainCLI to complete later.
        # We'll still monitor the capture stderr in background to log warnings.
        def _drain_err(pipe):
            try:
                for line in iter(pipe.readline, b''):
                    logging.debug('capture: %s', line.decode(errors='ignore').strip())
            except Exception:
                pass

        import threading
        threading.Thread(target=_drain_err, args=(cap_proc.stderr,), daemon=True).start()
    elif args.directory:
        d = Path(args.directory)
        if not d.is_dir():
            logging.error('Directory not found: %s', d)
            sys.exit(2)
        # find pcap files
        for ext in ('*.pcap', '*.pcapng'):
            pcaps.extend(sorted(d.glob(ext)))
        if not pcaps:
            logging.error('No pcap files found in directory: %s', d)
            sys.exit(2)

    # Output handling
    if args.csv:
        out_path = Path(args.output)
    else:
        # url mode
        out_path = None
        log_url = args.output

    temp_outputs = []
    try:
        for pcap in pcaps:
            if not pcap.exists():
                logging.error('PCAP not found: %s', pcap)
                continue
            if args.csv:
                # write per-pcap CSV into requested output dir or file
                if len(pcaps) == 1 and not args.merge:
                    target = out_path
                else:
                    # create outputs/<pcapname>_Flow.csv
                    outdir = out_path if out_path and out_path.is_dir() else Path('.').resolve()
                    target = outdir / (pcap.stem + '_Flow.csv')
                target.parent.mkdir(parents=True, exist_ok=True)
                log_url_for_maincli = 'http://localhost:0000'  # dummy valid http url to satisfy MainCLI validation (will not be used)
                # MainCLI requires a valid http(s) URL; use a localhost noop URL and ignore its effects
                ret = run_maincli(cic_dir, bin_dir, pcap, target, 'http://localhost:9101/predict/buffered', verbose=args.verbose)
                if ret != 0:
                    logging.error('CICFlowMeter failed for %s', pcap)
                else:
                    temp_outputs.append(target)
            else:
                # url mode: we need to provide MainCLI with an output path (it still writes a CSV) and the URL to post to
                tmpf = Path(tempfile.mkstemp(prefix='cfm_out_', suffix='_Flow.csv')[1])
                ret = run_maincli(cic_dir, bin_dir, pcap, tmpf, log_url, verbose=args.verbose)
                if ret != 0:
                    logging.error('CICFlowMeter failed for %s', pcap)
                else:
                    temp_outputs.append(tmpf)

        # handle merge
        if args.directory and args.merge and args.csv:
            # merge temp_outputs into single out_path
            if out_path is None:
                logging.error('merge requires an output path')
                sys.exit(2)
            merge_csvs(temp_outputs, out_path)
            final = out_path
        else:
            final = None
            if args.csv:
                if len(temp_outputs) == 1:
                    final = temp_outputs[0]
                else:
                    logging.info('Wrote per-pcap CSVs: %s', ', '.join(str(p) for p in temp_outputs))

        # handle fields filtering if requested
        if fields and args.csv and final:
            filtered = final.with_name(final.stem + '_filtered' + final.suffix)
            filter_csv_fields(final, filtered, fields)
            logging.info('Filtered CSV written to %s', filtered)

    finally:
        # if any temporary files were created for url mode, leave them (user may want them) or remove them
        pass


if __name__ == '__main__':
    main()
