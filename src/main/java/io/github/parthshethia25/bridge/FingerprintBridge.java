package io.github.parthshethia25.bridge;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.swing.*;
import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Properties;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicLong;

/** Burp 2026.7+ request hook: one curl_cffi send, then spoof the result into Burp. */
public final class FingerprintBridge implements BurpExtension, HttpHandler {
    private static final int MAX_REQUEST = 16 * 1024 * 1024;
    private final Semaphore capacity = new Semaphore(32);
    private final AtomicLong bridged = new AtomicLong();
    private final AtomicLong failures = new AtomicLong();
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    private volatile Settings settings = new Settings(false, "", "", "chrome");
    private volatile Process worker;
    private volatile String token;
    private volatile int port;
    private boolean supportedBurp;
    private MontoyaApi api;
    private Path dataDir;
    private volatile Path cachedBundledWorker;
    private JLabel status;
    private JLabel counters;
    private JTextField hostsField;
    private JTextField cookiesField;
    private JTextField pythonField;
    private JComboBox<String> profileField;
    private JCheckBox enabledBox;

    record Settings(boolean enabled, String hosts, String stripCookies, String profile) {
        boolean matches(String host) {
            String target = host.toLowerCase();
            for (String item : hosts.toLowerCase().split("[\\s,;]+")) {
                String rule = item.startsWith("*.") ? item.substring(2) : item;
                if (!rule.isBlank() && (target.equals(rule) || target.endsWith("." + rule))) return true;
            }
            return false;
        }
    }

    @Override public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Fingerprint Bridge");
        dataDir = Path.of(System.getProperty("user.home"), ".burp-fingerprint-bridge");
        String hosts = api.persistence().preferences().getString("bridge.hosts");
        String cookies = api.persistence().preferences().getString("bridge.cookies");
        String profile = api.persistence().preferences().getString("bridge.profile");
        Boolean enabled = api.persistence().preferences().getBoolean("bridge.enabled");
        // Optional deployment seed; Burp preferences take precedence after the first Apply.
        if (hosts == null && Files.exists(dataDir.resolve("settings.properties"))) {
            try (InputStream in = Files.newInputStream(dataDir.resolve("settings.properties"))) {
                Properties seed = new Properties();
                seed.load(in);
                hosts = seed.getProperty("hosts", "");
                cookies = seed.getProperty("stripCookies", "");
                profile = seed.getProperty("profile", "chrome");
                enabled = Boolean.parseBoolean(seed.getProperty("enabled", "false"));
            } catch (IOException ex) {
                api.logging().logToError("Fingerprint Bridge settings seed could not be read.");
            }
        }
        settings = new Settings(Boolean.TRUE.equals(enabled), hosts == null ? "" : hosts,
                cookies == null ? "" : cookies, profile == null ? "chrome" : profile);
        try {
            RequestToBeSentAction.class.getMethod("spoof", HttpResponse.class);
            supportedBurp = true;
        } catch (NoSuchMethodException ex) {
            api.logging().logToOutput("Fingerprint Bridge: using compatibility relay for this Burp version.");
        }
        api.http().registerHttpHandler(this);
        api.userInterface().registerSuiteTab("Fingerprint Bridge", buildUi());
        api.extension().registerUnloadingHandler(this::stopWorker);
        if (bundledWorker() != null || Files.exists(venvPython()))
            new Thread(() -> startWorker(false), "bridge-start").start();
        api.logging().logToOutput("Fingerprint Bridge loaded; configure hosts in its tab.");
    }

    private Component buildUi() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(18, 18, 18, 18));
        GridBagConstraints g = new GridBagConstraints();
        g.gridx = 0; g.gridy = 0; g.anchor = GridBagConstraints.WEST;
        g.insets = new Insets(4, 4, 4, 4);
        panel.add(new JLabel("Fingerprint Bridge — one upstream send per selected request"), g);
        g.gridy++; enabledBox = new JCheckBox("Enable for host list", settings.enabled());
        panel.add(enabledBox, g);
        g.gridy++; panel.add(new JLabel("Hosts (comma separated; subdomains included)"), g);
        g.gridy++; hostsField = new JTextField(settings.hosts(), 48); panel.add(hostsField, g);
        g.gridy++; panel.add(new JLabel("Strip these bot cookies on selected hosts (optional)"), g);
        g.gridy++; cookiesField = new JTextField(settings.stripCookies(), 48); panel.add(cookiesField, g);
        g.gridy++; panel.add(new JLabel("Browser TLS profile"), g);
        g.gridy++; profileField = new JComboBox<>(new String[]{"chrome", "firefox", "safari", "chrome_android", "safari_ios"});
        profileField.setSelectedItem(settings.profile()); panel.add(profileField, g);
        g.gridy++; panel.add(new JLabel("Python command (for first setup)"), g);
        g.gridy++; pythonField = new JTextField("python", 48); panel.add(pythonField, g);
        g.gridy++;
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JButton apply = new JButton("Apply");
        apply.addActionListener(e -> applySettings());
        JButton setup = new JButton("Set up and start worker");
        setup.addActionListener(e -> new Thread(() -> startWorker(true), "bridge-setup").start());
        JButton stop = new JButton("Stop worker");
        stop.addActionListener(e -> stopWorker());
        buttons.add(apply); buttons.add(setup); buttons.add(stop);
        panel.add(buttons, g);
        g.gridy++; status = new JLabel("Worker: checking"); panel.add(status, g);
        g.gridy++; counters = new JLabel("Bridged: 0   Failed: 0"); panel.add(counters, g);
        g.gridy++; panel.add(new JLabel("Tip: enter a hostname such as example.com; leave cookies blank unless needed"), g);
        g.gridy++; panel.add(new JLabel("Proxy, Repeater, Intruder and Burp Scanner use this hook. External network stacks may not."), g);
        g.gridy++; panel.add(new JLabel(supportedBurp ? "Mode: response spoof" : "Mode: compatibility relay (Burp may show the local relay request)"), g);
        new Timer(1000, e -> counters.setText("Bridged: " + bridged.get() + "   Failed: " + failures.get())).start();
        return new JScrollPane(panel);
    }

    private void applySettings() {
        settings = new Settings(enabledBox.isSelected(), hostsField.getText().trim(),
                cookiesField.getText().trim(), (String) profileField.getSelectedItem());
        api.persistence().preferences().setBoolean("bridge.enabled", settings.enabled());
        api.persistence().preferences().setString("bridge.hosts", settings.hosts());
        api.persistence().preferences().setString("bridge.cookies", settings.stripCookies());
        api.persistence().preferences().setString("bridge.profile", settings.profile());
        setStatus("Settings saved. Worker " + (worker != null && worker.isAlive() ? "ready" : "not running"));
    }

    private Path venvPython() {
        return dataDir.resolve("venv").resolve(System.getProperty("os.name").toLowerCase().contains("win")
                ? "Scripts/python.exe" : "bin/python");
    }

    private Path bundledWorker() {
        if (cachedBundledWorker != null) return cachedBundledWorker;
        boolean windows = System.getProperty("os.name").toLowerCase().contains("win");
        String name = windows ? "bridge-worker.exe" : "bridge-worker";
        try (InputStream in = getClass().getResourceAsStream("/native/" + name)) {
            if (in == null) return null;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[65536];
            int count;
            while ((count = in.read(buffer)) != -1) digest.update(buffer, 0, count);
            String hash = HexFormat.of().formatHex(digest.digest()).substring(0, 12);
            cachedBundledWorker = dataDir.resolve("bridge-worker-" + hash + (windows ? ".exe" : ""));
            return cachedBundledWorker;
        } catch (IOException | NoSuchAlgorithmException ex) {
            api.logging().logToError("Fingerprint Bridge could not inspect bundled worker.");
            return null;
        }
    }

    private void extractBundledWorker(Path destination) throws IOException {
        if (Files.exists(destination)) return;
        String resource = System.getProperty("os.name").toLowerCase().contains("win")
                ? "/native/bridge-worker.exe" : "/native/bridge-worker";
        try (InputStream in = getClass().getResourceAsStream(resource)) {
            if (in == null) throw new IOException("Bundled worker missing");
            Files.copy(in, destination);
        }
        destination.toFile().setExecutable(true);
    }

    private void extract(String name) throws IOException {
        try (InputStream in = getClass().getResourceAsStream("/python/" + name)) {
            if (in == null) throw new IOException("Missing packaged " + name);
            Files.copy(in, dataDir.resolve(name), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private int runCommand(String... args) throws IOException, InterruptedException {
        Process process = new ProcessBuilder(args).directory(dataDir.toFile()).redirectErrorStream(true).start();
        Thread drain = new Thread(() -> {
            try (InputStream in = process.getInputStream()) { in.transferTo(java.io.OutputStream.nullOutputStream()); }
            catch (IOException ignored) { }
        }, "bridge-setup-output");
        drain.setDaemon(true); drain.start();
        int code = process.waitFor();
        drain.join(1000);
        return code;
    }

    private synchronized void startWorker(boolean setup) {
        try {
            if (worker != null && worker.isAlive()) { setStatus("Worker already running"); return; }
            Files.createDirectories(dataDir);
            Path binary = bundledWorker();
            if (binary != null) {
                extractBundledWorker(binary);
            } else {
                extract("worker.py"); extract("requirements.txt");
                if (setup && !Files.exists(venvPython())) {
                    setStatus("Creating Python environment…");
                    if (runCommand(pythonField.getText().trim(), "-m", "venv", dataDir.resolve("venv").toString()) != 0)
                        throw new IOException("Python venv creation failed");
                }
                if (setup) {
                    setStatus("Installing Python dependencies…");
                    if (runCommand(venvPython().toString(), "-m", "pip", "install", "-r",
                            dataDir.resolve("requirements.txt").toString()) != 0)
                        throw new IOException("Dependency installation failed");
                }
                if (!Files.exists(venvPython())) { setStatus("Use Set up and start worker"); return; }
            }
            try (ServerSocket socket = new ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
                port = socket.getLocalPort();
            }
            byte[] secret = new byte[32]; new SecureRandom().nextBytes(secret);
            token = Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
            ProcessBuilder pb = binary == null
                    ? new ProcessBuilder(venvPython().toString(), "-u",
                        dataDir.resolve("worker.py").toString(), "--port", Integer.toString(port))
                    : new ProcessBuilder(binary.toString(), "--port", Integer.toString(port));
            pb.environment().put("BRIDGE_TOKEN", token);
            pb.directory(dataDir.toFile()).redirectErrorStream(true);
            worker = pb.start();
            Process started = worker;
            Thread drain = new Thread(() -> {
                try (InputStream in = started.getInputStream()) { in.transferTo(java.io.OutputStream.nullOutputStream()); }
                catch (IOException ignored) { }
            }, "bridge-worker-output");
            drain.setDaemon(true); drain.start();
            for (int i = 0; i < 50 && started.isAlive(); i++) {
                try {
                    HttpRequest health = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/health"))
                            .header("Authorization", "Bearer " + token).timeout(Duration.ofSeconds(1)).GET().build();
                    if (client.send(health, java.net.http.HttpResponse.BodyHandlers.discarding()).statusCode() == 200) {
                        setStatus("Worker ready on loopback"); return;
                    }
                } catch (Exception ignored) { }
                Thread.sleep(200);
            }
            throw new IOException("Worker did not become ready");
        } catch (Exception ex) {
            api.logging().logToError("Fingerprint Bridge worker setup failed: " + ex.getMessage());
            stopWorker();
            setStatus("Worker error: " + ex.getMessage());
        }
    }

    private synchronized void stopWorker() {
        Process old = worker; worker = null; token = null;
        if (old != null) {
            // PyInstaller one-file executables use a parent/child pair.
            old.descendants().forEach(ProcessHandle::destroy);
            old.destroy();
        }
        setStatus("Worker stopped");
    }

    private void setStatus(String value) {
        if (status != null) SwingUtilities.invokeLater(() -> status.setText(value));
    }

    @Override public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        Settings selected = settings;
        if (!selected.enabled()) return RequestToBeSentAction.continueWith(request);
        String host;
        try { host = URI.create(request.url()).getHost(); }
        catch (Exception ex) { return RequestToBeSentAction.continueWith(request); }
        if (host == null || !selected.matches(host)) return RequestToBeSentAction.continueWith(request);
        if (!supportedBurp) return relayAction(request, selected);
        if (request.body().length() > MAX_REQUEST) return failure(413, "Request exceeds 16 MiB bridge limit");
        if (!capacity.tryAcquire()) return failure(503, "Bridge busy (32 in flight)");
        try {
            Process active = worker;
            String secret = token;
            if (active == null || !active.isAlive() || secret == null) return failure(502, "Bridge worker unavailable");
            JsonObject payload = payload(request, selected);
            HttpRequest call = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/proxy"))
                    .header("Authorization", "Bearer " + secret).header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(35))
                    .POST(HttpRequest.BodyPublishers.ofString(payload.toString())).build();
            java.net.http.HttpResponse<String> received = client.send(call,
                    java.net.http.HttpResponse.BodyHandlers.ofString());
            if (received.statusCode() != 200) return failure(502, "Bridge transport failed");
            JsonObject result = JsonParser.parseString(received.body()).getAsJsonObject();
            int statusCode = result.get("status_code").getAsInt();
            String reason = result.get("reason").getAsString().replaceAll("[\\r\\n]", "");
            byte[] body = Base64.getDecoder().decode(result.get("body").getAsString());
            ByteArrayOutputStream raw = new ByteArrayOutputStream();
            raw.write(("HTTP/1.1 " + statusCode + " " + reason + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
            for (var entry : result.getAsJsonArray("headers")) {
                JsonArray pair = entry.getAsJsonArray();
                String name = pair.get(0).getAsString();
                String value = pair.get(1).getAsString();
                if (name.contains("\r") || name.contains("\n") || value.contains("\r") || value.contains("\n")) continue;
                raw.write((name + ": " + value + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
            }
            raw.write("\r\n".getBytes(StandardCharsets.ISO_8859_1));
            raw.write(body);
            bridged.incrementAndGet();
            return RequestToBeSentAction.spoof(HttpResponse.httpResponse(ByteArray.byteArray(raw.toByteArray())));
        } catch (Exception ex) {
            api.logging().logToError("Fingerprint Bridge request failed: " + ex.getClass().getSimpleName());
            return failure(502, "Bridge transport error");
        } finally {
            capacity.release();
        }
    }

    private JsonObject payload(HttpRequestToBeSent request, Settings selected) {
        JsonObject payload = new JsonObject();
        payload.addProperty("method", request.method());
        payload.addProperty("url", request.url());
        payload.addProperty("body", Base64.getEncoder().encodeToString(request.body().getBytes()));
        payload.addProperty("profile", selected.profile());
        payload.addProperty("timeout", 30);
        JsonArray headers = new JsonArray();
        for (HttpHeader h : request.headers()) {
            JsonArray pair = new JsonArray(); pair.add(h.name()); pair.add(h.value()); headers.add(pair);
        }
        payload.add("headers", headers);
        JsonArray strip = new JsonArray();
        for (String name : selected.stripCookies().split("[,;\\s]+"))
            if (!name.isBlank()) strip.add(name.trim());
        payload.add("strip_cookies", strip);
        return payload;
    }

    private RequestToBeSentAction relayAction(HttpRequestToBeSent request, Settings selected) {
        // Preserve the method, path, body and ordinary headers in Burp's UI.
        // Only the connection target changes to loopback. Signed metadata tells
        // the worker where to send the one actual upstream request.
        int relayPort = port > 0 ? port : 1;
        String target = request.url();
        String profile = selected.profile();
        String strip = selected.stripCookies();
        String time = Long.toString(System.currentTimeMillis() / 1000);
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec((token == null ? "" : token).getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            String prefix = request.method() + "\n" + target + "\n" + profile + "\n" + strip + "\n" + time + "\n";
            mac.update(prefix.getBytes(StandardCharsets.UTF_8));
            String signature = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mac.doFinal(request.body().getBytes()));
            var forwarded = request.withService(HttpService.httpService("127.0.0.1", relayPort, false))
                    .withUpdatedHeader("Host", "127.0.0.1:" + relayPort)
                    .withAddedHeader("X-Bridge-Target", target)
                    .withAddedHeader("X-Bridge-Profile", profile)
                    .withAddedHeader("X-Bridge-Strip-Cookies", strip)
                    .withAddedHeader("X-Bridge-Time", time)
                    .withAddedHeader("X-Bridge-Signature", signature);
            bridged.incrementAndGet();
            return RequestToBeSentAction.continueWith(forwarded);
        } catch (Exception ex) {
            failures.incrementAndGet();
            api.logging().logToError("Fingerprint Bridge relay failed: " + ex.getClass().getSimpleName());
            var deadEnd = request.withService(HttpService.httpService("127.0.0.1", 1, false));
            return RequestToBeSentAction.continueWith(deadEnd);
        }
    }

    private RequestToBeSentAction failure(int code, String message) {
        failures.incrementAndGet();
        String body = message + "\n";
        String response = "HTTP/1.1 " + code + " Bridge Error\r\nContent-Type: text/plain; charset=utf-8\r\n"
                + "Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length
                + "\r\nCache-Control: no-store\r\n\r\n" + body;
        return RequestToBeSentAction.spoof(HttpResponse.httpResponse(response));
    }

    @Override public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        return ResponseReceivedAction.continueWith(response);
    }
}
