import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class StreamGobbler implements Runnable {
    private InputStream inputStream;
    private String logUrl;
    private String prefix;

    public StreamGobbler(InputStream inputStream, String logUrl, String prefix) {
        this.inputStream = inputStream;
        this.logUrl = logUrl;
        this.prefix = prefix;
    }

    @Override
    public void run() {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String fullMessage = prefix + ": " + line;
                System.out.println(fullMessage);
                logToUrl(logUrl, fullMessage);
            }
        } catch (Exception e) {
            System.err.println("Error reading stream for " + prefix + ": " + e.getMessage());
            logToUrl(logUrl, "Error reading stream for " + prefix + ": " + e.getMessage());
        }
    }

    private void logToUrl(String logUrl, String message) {
        try {
            URL url = new URL(logUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json");

            String json = "{\"log\": \"" + message.replace("\"", "\\\"") + "\"}";

            try (OutputStream os = conn.getOutputStream()) {
                os.write(json.getBytes());
            }

            int responseCode = conn.getResponseCode();
            if (responseCode != 200 && responseCode != 201) {
                System.err.println("Failed to send log: " + responseCode + " for message: " + message);
            }
        } catch (Exception e) {
            System.err.println("Error sending log to URL: " + e.getMessage() + " for message: " + message);
        }
    }
}
