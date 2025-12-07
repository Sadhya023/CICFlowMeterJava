import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URI;
import java.io.InputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.io.RandomAccessFile;
import java.util.concurrent.atomic.AtomicBoolean;
import java.time.Instant;

public class MainCLI {
    // structured log entry
    private static final class LogEntry {
        final String time;
        final String stream;
        final String message;
        LogEntry(String stream, String message) {
            this.time = Instant.now().toString();
            this.stream = stream;
            this.message = message;
        }
    }
    // Queue and sender to stream live logs to remote HTTP endpoint without blocking main thread
    private static final BlockingQueue<LogEntry> logQueue = new LinkedBlockingQueue<>(10000);
    private static volatile boolean senderRunning = false;
    private static ExecutorService logSender = null;
    private static final boolean DEBUG = true; // set true while debugging locally

    private static void startLogSender(String url) {
        if (senderRunning) return;
        senderRunning = true;
        logSender = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "log-sender");
            t.setDaemon(true);
            return t;
        });
        logSender.submit(() -> {
            try {
                while (senderRunning || !logQueue.isEmpty()) {
                    LogEntry e = logQueue.poll(100, TimeUnit.MILLISECONDS);
                    if (e == null) continue;
                    // best-effort send; logToUrl already has timeouts
                    try {
                        if (DEBUG) System.err.println("SENDER: sending log: ["+e.stream+"] " + e.message);
                        logToUrl(url, e);
                    } catch (Throwable t) {
                        System.err.println("Log sender failed: " + t.getMessage());
                    }
                }
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
        });
    }

    private static void stopLogSender() {
        senderRunning = false;
        if (logSender != null) {
            // wait up to 5s for queue to drain before shutting
            long waitUntil = System.currentTimeMillis() + 5000;
            while (!logQueue.isEmpty() && System.currentTimeMillis() < waitUntil) {
                try { Thread.sleep(100); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); break; }
            }
            logSender.shutdown();
            try {
                logSender.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            logSender = null;
        }
    }

    private static void enqueueLog(String stream, String s) {
        if (s == null) return;
        // best-effort - drop if full
        logQueue.offer(new LogEntry(stream, s));
        if (DEBUG) System.err.println("ENQUEUE: ["+stream+"] " + s);
    }

    // Tail a file and enqueue any appended lines (best-effort). Returns the tail thread.
    private static Thread tailFileAndEnqueue(Path file, String streamName, AtomicBoolean running) {
        Thread t = new Thread(() -> {
            long pointer = 0;
            while (running.get()) {
                try {
                    if (Files.exists(file)) {
                        try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "r")) {
                            long len = raf.length();
                            if (pointer > len) pointer = 0; // file rotated/truncated
                            raf.seek(pointer);
                            String line;
                            while ((line = raf.readLine()) != null) {
                                // RandomAccessFile.readLine uses ISO-8859-1; convert to UTF-8
                                String decoded = new String(line.getBytes("ISO-8859-1"), StandardCharsets.UTF_8);
                                enqueueLog(streamName, decoded);
                            }
                            pointer = raf.getFilePointer();
                        }
                    }
                    Thread.sleep(100);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    // best-effort: don't crash tail thread
                    System.err.println("Tailer error for " + file + ": " + e.getMessage());
                    try { Thread.sleep(500); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); break; }
                }
            }
        }, "tail-" + streamName);
        t.setDaemon(true);
        t.start();
        return t;
    }

    public static void main(String[] args) {
        if (args.length < 3) {
            System.out.println("Usage: java MainCLI <input_pcap> <output_csv> <log_url>");
            return;
        }

        String inputPcap = args[0];
        String outputCsv = args[1];
        String logUrl = args[2];

        // Validate input file
        Path inputPath = Paths.get(inputPcap);
        if (!Files.exists(inputPath) || !Files.isReadable(inputPath)) {
            System.err.println("Input pcap does not exist or is not readable: " + inputPcap);
            return;
        }

        // Validate output parent directory is writable (if provided)
        Path outputPath = Paths.get(outputCsv);
        Path parent = outputPath.getParent();
        if (parent != null && !Files.exists(parent)) {
            try {
                Files.createDirectories(parent);
            } catch (IOException e) {
                System.err.println("Cannot create output directory: " + parent + " - " + e.getMessage());
                return;
            }
        }

        // Basic validation of URL scheme
        if (!isHttpUrl(logUrl)) {
            System.err.println("log_url must be an http or https URL: " + logUrl);
            return;
        }

        // start background sender and enqueue initial status message
        startLogSender(logUrl);
        enqueueLog("SYSTEM", "Starting processing: " + inputPcap);

        try {
            // Use platform path separator and prefer java from java.home
            String pathSep = java.io.File.pathSeparator;
            String javaExe = Paths.get(System.getProperty("java.home"), "bin", "java").toString();
            String classpath = "lib/*" + pathSep + ".";

            ProcessBuilder pb = new ProcessBuilder(
                    javaExe, "-cp", classpath, "cic.cs.unb.ca.ifm.App",
                    "-f", inputPcap, "-o", outputCsv);

            // Resolve CICFlowMeter-4.0 directory relative to current working directory
            Path cwd = Paths.get("").toAbsolutePath();
            Path cfmDir = cwd.resolve("CICFlowMeter-4.0");
            if (Files.exists(cfmDir) && Files.isDirectory(cfmDir)) {
                pb.directory(cfmDir.toFile());
            }

            Process process = pb.start();

            // Consume stdout and stderr to avoid blocking and stream lines to remote URL
            Thread outGob = streamLinesToOutputAndEnqueue(process.getInputStream(), System.out, "STDOUT");
            Thread errGob = streamLinesToOutputAndEnqueue(process.getErrorStream(), System.err, "STDERR");

            // Start tailing the output CSV file(s) so we can capture live flow rows.
            AtomicBoolean tailerRunning = new AtomicBoolean(true);
            Thread tail1 = null;
            Thread tail2 = null;
            Thread scanner = null;
            try {
                Path outPath = Paths.get(outputCsv);
                java.util.List<Path> candidates = new java.util.ArrayList<>();
                // 1) cwd resolve of given outputCsv (covers when user passed a path relative to repo root)
                candidates.add(cwd.resolve(outPath).normalize());
                // 2) if pb.directory is set, resolve relative to that (covers typical child working dir)
                if (pb.directory() != null) {
                    candidates.add(pb.directory().toPath().resolve(outPath).normalize());
                    // also try pb.directory()/output/<filename>
                    candidates.add(pb.directory().toPath().resolve("output").resolve(outPath.getFileName()).normalize());
                    // also try pb.directory()/<filename> (in case child writes to working dir)
                    candidates.add(pb.directory().toPath().resolve(outPath.getFileName()).normalize());
                }
                // 3) absolute path if provided
                if (outPath.isAbsolute()) candidates.add(outPath.normalize());

                // start tailers for unique candidate paths (limit to 4)
                java.util.Set<String> seen = new java.util.HashSet<>();
                int started = 0;
                for (Path p : candidates) {
                    String key = p.toAbsolutePath().normalize().toString();
                    if (seen.contains(key)) continue;
                    seen.add(key);
                    if (started == 0) tail1 = tailFileAndEnqueue(p, "FLOW", tailerRunning);
                    else if (started == 1) tail2 = tailFileAndEnqueue(p, "FLOW", tailerRunning);
                    else tailFileAndEnqueue(p, "FLOW", tailerRunning); // extra, but harmless
                    started++;
                    if (started >= 4) break;
                }

                Path childOut = cwd.resolve(outPath).normalize();
                Path altOut = null;
                // 2nd pass to detect symlinks (like ../output/file.csv)
                try {
                    java.util.Set<Path> tried = new java.util.HashSet<>();
                    for (Path p : candidates) {
                        if (tried.contains(p)) continue;
                        tried.add(p);
                        Path resolved = p.toRealPath();
                        if (!resolved.equals(p) && Files.isRegularFile(resolved)) {
                            // found a symlink target that is a regular file
                            if (seen.add(resolved.toAbsolutePath().normalize().toString())) {
                                // not seen yet, start tailer
                                tailFileAndEnqueue(resolved, "FLOW", tailerRunning);
                            }
                        }
                    }
                } catch (Exception ignore) {}

                // also try common child output locations (data/daily, bin/data/daily, output/)
                try {
                    Path dataDir = cwd.resolve("data").resolve("daily");
                    if (Files.isDirectory(dataDir)) {
                        try (java.util.stream.Stream<Path> stream = Files.list(dataDir)) {
                            stream.filter(p -> Files.isRegularFile(p))
                                  .forEach(p -> {
                                      String name = p.getFileName().toString();
                                      if ((name.toLowerCase().contains("flow") || name.toLowerCase().endsWith(".csv")) ) {
                                          String key = p.toAbsolutePath().normalize().toString();
                                          if (seen.add(key)) {
                                              tailFileAndEnqueue(p, "FLOW", tailerRunning);
                                          }
                                      }
                                  });
                        }
                    }
                } catch (Exception ignore) {}

                // if nothing started yet, just tail the original outputCsv
                if (started == 0) {
                    tail1 = tailFileAndEnqueue(childOut, "FLOW", tailerRunning);
                    if (altOut != null && !altOut.equals(childOut)) {
                        tail2 = tailFileAndEnqueue(altOut, "FLOW", tailerRunning);
                    }
                }

                // Start a small scanner thread to discover flow files created later in common folders
                scanner = new Thread(() -> {
                     java.util.Set<String> tailed = new java.util.HashSet<>();
                     java.util.List<Path> scanDirs = new java.util.ArrayList<>();
                    // add pb.directory(), pb.directory()/data, pb.directory()/bin/data/daily, cwd/data/daily
                    if (pb.directory() != null) {
                        scanDirs.add(pb.directory().toPath());
                        scanDirs.add(pb.directory().toPath().resolve("data"));
                        scanDirs.add(pb.directory().toPath().resolve("bin").resolve("data").resolve("daily"));
                        scanDirs.add(pb.directory().toPath().resolve("output"));
                    }
                    scanDirs.add(cwd.resolve("data").resolve("daily"));
                    scanDirs.add(cwd.resolve("output"));
                    while (tailerRunning.get()) {
                        try {
                            for (Path d : scanDirs) {
                                try {
                                    if (!Files.isDirectory(d)) continue;
                                    try (java.util.stream.Stream<Path> stream = Files.list(d)) {
                                        stream.filter(p -> Files.isRegularFile(p))
                                              .forEach(p -> {
                                                  String name = p.getFileName().toString();
                                                  if ((name.toLowerCase().contains("flow") || name.toLowerCase().endsWith(".csv")) ) {
                                                      String key = p.toAbsolutePath().normalize().toString();
                                                      if (tailed.contains(key)) return;
                                                      tailed.add(key);
                                                      // start a tailer for discovered flow file
                                                      tailFileAndEnqueue(p, "FLOW", tailerRunning);
                                                  }
                                              });
                                    }
                                } catch (Exception ignore) {}
                            }
                            Thread.sleep(500);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                    }
                }, "flow-scanner");
                scanner.setDaemon(true);
                scanner.start();
             } catch (Exception e) {
                 System.err.println("Failed to start file tailer: " + e.getMessage());
             }

            int exitCode = process.waitFor();

            // Ensure gobblers finished
            outGob.join();
            errGob.join();

            // stop tailers and wait a bit for them to flush
            if (tail1 != null || tail2 != null) {
                try {
                    tailerRunning.set(false);
                    if (tail1 != null) tail1.join(1000);
                    if (tail2 != null) tail2.join(1000);
                    // also stop the scanner if it was started
                    try { if (scanner != null) scanner.join(500); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }

            if (exitCode != 0) {
                enqueueLog("SYSTEM", "CICFlowMeter exited with code: " + exitCode);
                // Propagate non-zero exit so callers can detect failure
                // stop any running tailers and scanner
                try { tailerRunning.set(false); } catch (Exception ignore) {}
                if (tail1 != null) try { tail1.join(1000); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                if (tail2 != null) try { tail2.join(1000); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                try { if (scanner != null) scanner.join(500); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                stopLogSender();
                System.exit(exitCode);
            }
        } catch (Exception e) {
            enqueueLog("SYSTEM", "Error during processing: " + fullStackTrace(e));
            System.err.println("Processing failed: " + e.getMessage());
            // stop tailers if any
            try { Thread.sleep(50); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
            stopLogSender();
            return;
        }

        // finish: ensure the final message is sent via the background sender
        enqueueLog("SYSTEM", "Finished processing: " + inputPcap);
        // give sender a moment to flush then stop it
        try {
            Thread.sleep(500);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
        // ensure tailers are stopped
        try { Thread.sleep(200); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
        stopLogSender();
        System.out.println("Processing complete. Output: " + outputCsv);
    }

    private static boolean isHttpUrl(String url) {
        try {
            URI u = URI.create(url);
            String proto = u.getScheme();
            return "http".equalsIgnoreCase(proto) || "https".equalsIgnoreCase(proto);
        } catch (Exception e) {
            return false;
        }
    }

    // Read stream line-by-line, write to the provided PrintStream, and enqueue each line to the remote log
    private static Thread streamLinesToOutputAndEnqueue(final InputStream in, final java.io.PrintStream out, final String streamName) {
        Thread t = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    out.println(line);
                    enqueueLog(streamName, line);
                }
            } catch (IOException e) {
                // best-effort logging
                System.err.println("Stream gobbler error: " + e.getMessage());
            }
        });
        t.setDaemon(true);
        t.start();
        return t;
    }

    private static void logToUrl(String logUrl, LogEntry entry) {
        HttpURLConnection conn = null;
        try {
            URI uri = URI.create(logUrl);
            URL url = uri.toURL();
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");

            // structured JSON with time, stream, log
            StringBuilder json = new StringBuilder();
            json.append('{');
            json.append("\"time\": \"").append(escapeJson(entry.time)).append('\"');
            json.append(',');
            json.append("\"stream\": \"").append(escapeJson(entry.stream)).append('\"');
            json.append(',');
            json.append("\"log\": \"").append(escapeJson(entry.message)).append('\"');
            json.append('}');

            byte[] bytes = json.toString().getBytes(StandardCharsets.UTF_8);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(bytes);
            }

            int responseCode = conn.getResponseCode();
            if (responseCode / 100 != 2) { // accept any 2xx
                String respBody = readStream(conn.getErrorStream());
                System.err.println("Failed to send log: " + responseCode + " body=" + respBody);
            }
            else {
                // optionally print a debug line locally; commented out to avoid noise
                // System.out.println("Log sent: " + message);
            }
        } catch (Exception e) {
            System.err.println("Error sending log: " + e.getMessage());
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private static String readStream(InputStream is) {
        if (is == null) return "";
        try (InputStream in = is) {
            byte[] buf = new byte[4096];
            StringBuilder sb = new StringBuilder();
            int r;
            while ((r = in.read(buf)) != -1) {
                sb.append(new String(buf, 0, r, StandardCharsets.UTF_8));
            }
            return sb.toString();
        } catch (IOException e) {
            return "(error reading response: " + e.getMessage() + ")";
        }
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        // minimal escaping for JSON strings
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"': sb.append("\\\""); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int)c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    private static String fullStackTrace(Throwable t) {
        StringWriter sw = new StringWriter();
        t.printStackTrace(new PrintWriter(sw));
        return sw.toString();
    }
}
