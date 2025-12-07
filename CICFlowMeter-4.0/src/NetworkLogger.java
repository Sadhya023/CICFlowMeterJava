import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class NetworkLogger {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Usage: java -cp <bin;lib/*> NetworkLogger <interfaceName> <log_url>");
            return;
        }
        String interfaceName = args[0];
        String logUrl = args[1];

        PcapNetworkInterface nif = Pcaps.getDevByName(interfaceName);
        if (nif == null) {
            System.err.println("Network interface not found: " + interfaceName);
            return;
        }
        System.out.println("Capturing on interface: " + interfaceName);
        PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

        PacketListener listener = packet -> {
            String logMsg = "Packet: " + packet;
            logToUrl(logUrl, logMsg);
        };

        handle.loop(-1, listener);
    }

    private static void logToUrl(String logUrl, String message) {
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
                System.err.println("Failed to send log: " + responseCode);
            }
        } catch (Exception e) {
            System.err.println("Error sending log: " + e.getMessage());
        }
    }
}
