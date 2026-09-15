package com.okta.webservice.config;

import com.okta.webservice.utils.OktaOpaExplorerBridge;
import com.okta.webservice.utils.OktaSystemLogChecker;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.List;
import java.util.Set;
import java.util.Properties;

/**
 * Loads and caches connector-azure configuration from OPA or a local JSON file.
 *
 * Priority:
 *   1. OPA (via okta-opa-explorer JAR) -- if REST_CONNECTOR_NAME env var is set
 *   2. Local JSON file (CONNECTOR_REST_CONFIG_PATH env var or property)
 *
 * OPA connectivity is handled entirely by the bundled okta-opa-explorer JAR.
 * The JAR reads its credentials from: /run/config/oktaopaapiexplorer.config
 * (properties keys: opa.base.url, team.name, api.key.id, api.key.secret, project.name)
 *
 * Cache behaviour:
 *   - Populated on startup via @PostConstruct
 *   - In OPA mode: refreshed automatically every OPA_REFRESH_INTERVAL_SECONDS (5 min)
 *   - forceRefreshFromOpa() triggers an immediate re-fetch (called on Azure 401)
 */
@Component
public class ConnectorRestConfigLoader {

    private static final Logger logger = LogManager.getLogger(ConnectorRestConfigLoader.class);

    /** Env var holding connector name(s) to fetch from OPA */
    private static final String ENV_CONNECTOR_NAMES = "REST_CONNECTOR_NAME";

    /** Fallback paths for local-file mode */
    private static final String FALLBACK_DEFAULT_CONFIG_PATH = "/run/secrets/connector-azure/okta-config.json";
    private static final String FALLBACK_ENV_CONFIG_PATH     = "CONNECTOR_REST_CONFIG_PATH";

    /** How often (seconds) the OPA cache is refreshed to pick up rotated secrets */
    private static final long OPA_REFRESH_INTERVAL_SECONDS = 300;

    // ---------------------------------------------------------------
    // Cache state
    // ---------------------------------------------------------------
    private volatile ConnectorRestConfig cachedConfig;
    /** Timestamp of the last successful OPA load (Instant.EPOCH = never loaded) */
    private volatile Instant lastOpaLoadTime = Instant.EPOCH;
    /** Timestamp of the last System Log check (Tier-1 fast rotation detection) */
    private volatile Instant lastSystemLogCheck = Instant.EPOCH;

    // ---------------------------------------------------------------
    // Spring properties (local-file mode)
    // ---------------------------------------------------------------
    @Value("${connector.rest.config.default-path:/run/secrets/connector-azure/okta-config.json}")
    private String defaultConfigPath;

    @Value("${connector.rest.config.env-var:CONNECTOR_REST_CONFIG_PATH}")
    private String envConfigPath;

    @Value("${connector.rest.config.path:#{null}}")
    private String configPathProperty;

    // ---------------------------------------------------------------
    // Lifecycle
    // ---------------------------------------------------------------

    /**
     * Eagerly populates the cache before the first request arrives.
     */
    @PostConstruct
    public void initCache() {
        logger.info("Connector starting -- initializing configuration cache...");
        try {
            loadConfig();
            logger.info("Configuration cache initialized ({} server(s))",
                    cachedConfig != null && cachedConfig.getServers() != null
                            ? cachedConfig.getServers().size() : 0);
        } catch (Exception e) {
            logger.error("Failed to initialize configuration cache on startup: {}", e.getMessage());
        }
    }

    // ---------------------------------------------------------------
    // Public API
    // ---------------------------------------------------------------

    /**
     * Returns the active configuration, refreshing from OPA if the TTL has expired.
     * On the very first call (cache empty) it performs a full load.
     */
    public ConnectorRestConfig getConfig() throws IOException {
        if (cachedConfig == null) {
            loadConfig();
        } else {
            refreshOpaIfExpired();
        }
        return cachedConfig;
    }

    /**
     * Forces an immediate re-fetch from OPA and replaces the cache.
     * Called by the user controller when Azure returns HTTP 401 (stale client_secret).
     */
    public synchronized void forceRefreshFromOpa() {
        String rawConnectorNames = System.getenv(ENV_CONNECTOR_NAMES);
        List<String> connectorNames = resolveConnectorNames(rawConnectorNames);
        if (connectorNames.isEmpty()) {
            logger.warn("forceRefreshFromOpa: not in OPA mode -- clearing cache to force local file reload");
            cachedConfig = null;
            return;
        }
        logger.info("Force-refreshing connector config from OPA (triggered by Azure auth failure)...");
        cachedConfig = null;
        lastOpaLoadTime = Instant.EPOCH;
        try {
            loadConfigFromOpa(connectorNames);
            logger.info("Force-refresh complete ({} server(s))",
                    cachedConfig != null && cachedConfig.getServers() != null
                            ? cachedConfig.getServers().size() : 0);
        } catch (Exception e) {
            logger.warn("Force-refresh failed: {}", e.getMessage());
        }
    }

    /**
     * Clears the cache (useful for testing or manual reload via admin endpoint).
     */
    public synchronized void clearCache() {
        logger.debug("Clearing cached connector configuration");
        cachedConfig = null;
        lastOpaLoadTime = Instant.EPOCH;
    }

    // ---------------------------------------------------------------
    // Internal load methods
    // ---------------------------------------------------------------

    /**
     * Loads configuration from OPA (preferred) or local file on cache miss.
     */
    public synchronized ConnectorRestConfig loadConfig() throws IOException {
        if (cachedConfig != null) {
            return cachedConfig;
        }

        String rawConnectorNames = System.getenv(ENV_CONNECTOR_NAMES);
        List<String> connectorNames = resolveConnectorNames(rawConnectorNames);
        if (!connectorNames.isEmpty()) {
            logger.info("OPA mode active ({}={})", ENV_CONNECTOR_NAMES, rawConnectorNames);
            try {
                loadConfigFromOpa(connectorNames);
                return cachedConfig;
            } catch (Exception e) {
                logger.warn("Failed to load config from OPA: {} -- falling back to local file", e.getMessage());
            }
        }

        loadConfigFromFile();
        return cachedConfig;
    }

    /**
     * Loads each connector's configuration from OPA using the okta-opa-explorer JAR.
     *
     * The JAR (com.example.OktaOpaApiExplorer) manages all OPA connectivity:
     *   - Reads credentials from /run/config/oktaopaapiexplorer.config
     *   - Authenticates to OPA and obtains a service token
     *   - Fetches the secret encrypted with a per-request ephemeral RSA-2048 key (JWE)
     *   - Decrypts and returns the plaintext JSON object
     *
     * @param connectorNames resolved connector/secret names
     */
    private void loadConfigFromOpa(List<String> connectorNames) throws Exception {
        logger.info("Loading connector configuration from OPA for: {}", String.join(",", connectorNames));
        Map<String, ConnectorRestServerConfig> serverByName = new LinkedHashMap<>();

        for (String name : connectorNames) {

            logger.info("Fetching OPA secret for connector: {}", name);
            JSONObject secret = OktaOpaExplorerBridge.retrieveConnectorConfiguration(name);

            if (secret == null) {
                logger.warn("OPA returned null for connector '{}' -- skipping", name);
                continue;
            }

            List<ConnectorRestServerConfig> parsedServers = parseServersFromOpaSecret(secret, name);
            for (ConnectorRestServerConfig server : parsedServers) {
                serverByName.put(server.getName(), server);
                logger.info("Successfully loaded server from OPA: {}", server.getName());
            }
        }

        List<ConnectorRestServerConfig> servers = new ArrayList<>(serverByName.values());
        if (servers.isEmpty()) {
            throw new IllegalStateException("No servers loaded from OPA for: " + String.join(",", connectorNames));
        }

        cachedConfig   = new ConnectorRestConfig(servers);
        lastOpaLoadTime = Instant.now();
        logger.info("OPA configuration loaded -- {} server(s) cached", servers.size());
    }

    /**
     * Loads configuration from the local JSON file (fallback / non-OPA environments).
     */
    private void loadConfigFromFile() throws IOException {
        String configPath = getConfigPath();
        logger.info("Loading connector configuration from file: {}", configPath);

        File configFile = new File(configPath);
        if (!configFile.exists()) {
            throw new IOException("Configuration file not found at: " + configPath);
        }

        try {
            ObjectMapper mapper = new ObjectMapper();
            cachedConfig = mapper.readValue(configFile, ConnectorRestConfig.class);

            if (!cachedConfig.isValid()) {
                throw new IOException("Configuration is invalid: missing required fields");
            }

            logger.info("Loaded {} server(s) from file",
                    cachedConfig.getServers() != null ? cachedConfig.getServers().size() : 0);

            if (cachedConfig.getServers() != null) {
                for (ConnectorRestServerConfig server : cachedConfig.getServers()) {
                    logger.info("Registered server: {}", server.getName());
                }
            }
        } catch (IOException e) {
            logger.error("Failed to load configuration from file: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Two-tier secret-change detection:
     *
     * Tier 1 — Okta System Log (every request, lightweight GET):
     *   Delegates to OktaSystemLogChecker which calls OktaOpaApiExplorer.getOktaOpaServiceToken()
     *   from the bundled JAR for auth — no duplicate OPA credential code.
     *   If a PAM secret change event is found → forces an immediate re-fetch.
     *
     * Tier 2 — Full OPA re-fetch safety net (every 5 min):
     *   Regardless of System Log results, re-fetches all secrets from OPA every
     *   OPA_REFRESH_INTERVAL_SECONDS to guarantee eventual consistency.
     *
    * Only runs in OPA mode (REST_CONNECTOR_NAME env var set). No-op otherwise.
     */
    private synchronized void refreshOpaIfExpired() {
        String rawConnectorNames = System.getenv(ENV_CONNECTOR_NAMES);
        List<String> connectorNames = resolveConnectorNames(rawConnectorNames);
        if (connectorNames.isEmpty()) {
            return; // local-file mode -- no TTL refresh
        }

        long now     = Instant.now().getEpochSecond();
        long elapsed = now - lastOpaLoadTime.getEpochSecond();

        // -- Tier 1: Okta System Log event check (every request) ------------------
        // Uses OktaOpaApiExplorer.getOktaOpaServiceToken() internally — no OPA
        // credentials duplicated here.
        Instant checkSince = lastSystemLogCheck.equals(Instant.EPOCH)
                ? Instant.now().minusSeconds(OPA_REFRESH_INTERVAL_SECONDS)
                : lastSystemLogCheck;
        lastSystemLogCheck = Instant.now();

        boolean eventDetected = OktaSystemLogChecker.hasSecretChangedSince(checkSince, null);
        if (eventDetected) {
            logger.info("System Log event detected secret change -- forcing immediate OPA re-fetch");
            lastOpaLoadTime = Instant.EPOCH;  // force Tier-2 to run now
            elapsed = OPA_REFRESH_INTERVAL_SECONDS; // satisfy the condition below
        }

        // -- Tier 2: Full OPA re-fetch (every 5 min or when event detected) --------
        if (elapsed < OPA_REFRESH_INTERVAL_SECONDS) {
            logger.debug("OPA cache still fresh ({}s elapsed, TTL={}s)", elapsed, OPA_REFRESH_INTERVAL_SECONDS);
            return;
        }

        String trigger = eventDetected ? "System Log event" : elapsed + "s TTL interval";
        logger.info("OPA re-fetch triggered by {} -- refreshing config", trigger);
        try {
            Map<String, ConnectorRestServerConfig> freshServerByName = new LinkedHashMap<>();
            for (String name : connectorNames) {
                JSONObject secret = OktaOpaExplorerBridge.retrieveConnectorConfiguration(name);
                if (secret == null) {
                    logger.warn("OPA returned null for '{}' during refresh -- skipping", name);
                    continue;
                }
                List<ConnectorRestServerConfig> parsedServers = parseServersFromOpaSecret(secret, name);
                for (ConnectorRestServerConfig server : parsedServers) {
                    freshServerByName.put(server.getName(), server);
                    logger.debug("Refreshed server from OPA: {}", server.getName());
                }
            }

            List<ConnectorRestServerConfig> freshServers = new ArrayList<>(freshServerByName.values());
            if (!freshServers.isEmpty()) {
                cachedConfig    = new ConnectorRestConfig(freshServers);
                lastOpaLoadTime = Instant.now();
                logger.info("OPA cache refreshed ({}) -- {} server(s)", trigger, freshServers.size());
            } else {
                logger.warn("OPA refresh returned no servers -- keeping previous cache");
            }
        } catch (Exception e) {
            logger.warn("OPA refresh failed (keeping cached values): {}", e.getMessage());
        }
    }

    private List<String> resolveConnectorNames(String rawConnectorNames) {
        if (rawConnectorNames == null || rawConnectorNames.isBlank()) {
            return discoverConnectorNamesFromOpaSecrets();
        }

        String trimmed = rawConnectorNames.trim();
        if (!trimmed.contains(",")) {
            // Single value can represent either a connector name or a folder.
            // Try OPA list discovery first; if that is unavailable, fall back to the explicit name.
            List<String> discovered = discoverConnectorNamesFromOpaSecrets();
            if (!discovered.isEmpty()) {
                return discovered;
            }
            logger.info("OPA secret discovery unavailable; falling back to explicit {} value '{}'", ENV_CONNECTOR_NAMES, trimmed);
            return List.of(trimmed);
        }

        Set<String> names = new LinkedHashSet<>();
        for (String name : trimmed.split(",")) {
            String normalized = name.trim();
            if (!normalized.isEmpty()) {
                names.add(normalized);
            }
        }
        return new ArrayList<>(names);
    }

    private List<String> discoverConnectorNamesFromOpaSecrets() {
        try {
            OpaBootstrapConfig bootstrapConfig = loadBootstrapConfig();
            String serviceToken = OktaOpaExplorerBridge.getOktaOpaServiceToken();
            String listUrl = String.format(
                    "%s/v1/teams/%s/resource_groups/%s/projects/%s/secrets",
                    bootstrapConfig.opaBaseUrl(),
                    bootstrapConfig.teamName(),
                    bootstrapConfig.resourceId(),
                    bootstrapConfig.projectId());

            String responseBody = httpGet(listUrl, serviceToken);
            List<String> names = extractSecretNames(responseBody);
            logger.info("OPA secret discovery found {} connector name(s) from {}: {}",
                    names.size(), listUrl, names);
            return names;
        } catch (Exception e) {
            logger.warn("OPA secret discovery failed: {}", e.getMessage());
            return List.of();
        }
    }

    private OpaBootstrapConfig loadBootstrapConfig() throws IOException {
        String configPath = "/run/config/oktaopaapiexplorer.config";
        Properties props = new Properties();
        try (var input = Files.newInputStream(Path.of(configPath))) {
            props.load(input);
        }

        String opaBaseUrl = firstNonBlank(props,
                "opa.base.url",
                "opa_base_url");
        String teamName = firstNonBlank(props,
                "team.name",
                "team_name");
        String projectId = firstNonBlank(props,
                "projectId",
                "project.id");
        String resourceId = firstNonBlank(props,
                "resourceId",
                "resource.id");

        if (opaBaseUrl.isBlank() || teamName.isBlank() || projectId.isBlank() || resourceId.isBlank()) {
            throw new IOException("Missing OPA bootstrap config values required for secret listing");
        }

        return new OpaBootstrapConfig(opaBaseUrl.trim(), teamName.trim(), projectId.trim(), resourceId.trim());
    }

    private String firstNonBlank(Properties props, String... keys) {
        for (String key : keys) {
            String value = props.getProperty(key);
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return "";
    }

    private String httpGet(String urlString, String serviceToken) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(urlString).openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Authorization", "Bearer " + serviceToken);
        conn.setRequestProperty("Accept", "application/json");

        int code = conn.getResponseCode();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                code >= 400 ? conn.getErrorStream() : conn.getInputStream(), StandardCharsets.UTF_8))) {
            StringBuilder body = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                body.append(line);
            }
            if (code >= 400) {
                throw new IOException("OPA secret listing returned HTTP " + code + ": " + body);
            }
            return body.toString();
        }
    }

    private List<String> extractSecretNames(String responseBody) {
        Set<String> names = new LinkedHashSet<>();
        if (responseBody == null || responseBody.isBlank()) {
            return new ArrayList<>();
        }

        Object parsed;
        String trimmed = responseBody.trim();
        if (trimmed.startsWith("[")) {
            parsed = new JSONArray(trimmed);
        } else {
            parsed = new JSONObject(trimmed);
        }

        collectNames(parsed, names);
        return new ArrayList<>(names);
    }

    private void collectNames(Object node, Set<String> names) {
        if (node instanceof JSONArray array) {
            for (int i = 0; i < array.length(); i++) {
                collectNames(array.get(i), names);
            }
            return;
        }

        if (node instanceof JSONObject object) {
            if (object.has("name")) {
                String name = object.optString("name", "").trim();
                if (!name.isBlank()) {
                    names.add(name);
                }
            }
            if (object.has("secret_name")) {
                String name = object.optString("secret_name", "").trim();
                if (!name.isBlank()) {
                    names.add(name);
                }
            }
            if (object.has("secretId")) {
                String name = object.optString("secretId", "").trim();
                if (!name.isBlank()) {
                    names.add(name);
                }
            }
            if (object.has("scrtId")) {
                String name = object.optString("scrtId", "").trim();
                if (!name.isBlank()) {
                    names.add(name);
                }
            }

            for (String key : object.keySet()) {
                Object value = object.opt(key);
                if (value instanceof JSONArray || value instanceof JSONObject) {
                    collectNames(value, names);
                }
            }
        }
    }

    private record OpaBootstrapConfig(String opaBaseUrl, String teamName, String projectId, String resourceId) {
    }

    // ---------------------------------------------------------------
    // Parsing helpers
    // ---------------------------------------------------------------

    /**
     * Maps fields from the decrypted OPA secret JSON to a ConnectorRestServerConfig.
     * All fields are optional-with-defaults so a missing key never throws.
     */
    /**
     * @param connectorName the name used to fetch the secret from OPA; used as
     *                      the server name when the secret payload has no "name" field
     */
    private List<ConnectorRestServerConfig> parseServersFromOpaSecret(JSONObject secret, String connectorName) {
        try {
            // The OPA secret may be a nested structure with a "servers" array
            // (same format as docker/okta-config.json) or a flat object.
            // Mirror the SSH connector's parseOpaResponse logic, but keep all servers.
            List<ConnectorRestServerConfig> servers = new ArrayList<>();
            if (secret.has("servers") && !secret.isNull("servers")) {
                org.json.JSONArray serverArray = secret.getJSONArray("servers");
                if (serverArray.length() == 0) {
                    logger.warn("OPA secret for '{}' has an empty servers array", connectorName);
                    return List.of();
                }
                for (int i = 0; i < serverArray.length(); i++) {
                    JSONObject entry = serverArray.getJSONObject(i);
                    ConnectorRestServerConfig server = mapServerFromFlatSecret(entry, connectorName);
                    if (server != null) {
                        servers.add(server);
                    }
                }
            } else {
                ConnectorRestServerConfig server = mapServerFromFlatSecret(secret, connectorName);
                if (server != null) {
                    servers.add(server);
                }
            }

            return servers;
        } catch (Exception e) {
            logger.error("Failed to parse server from OPA secret: {}", e.getMessage());
            return List.of();
        }
    }

    private ConnectorRestServerConfig mapServerFromFlatSecret(JSONObject flat, String connectorName) {
        try {
            logger.debug("OPA secret keys for '{}': {}", connectorName, flat.keySet());

            ConnectorRestServerConfig server = new ConnectorRestServerConfig();

            // OPA secrets often omit the "name" field — fall back to the connector name
            String secretName = flat.optString("name", "");
            server.setName(secretName.isBlank() ? connectorName : secretName);

            String authToken = flat.optString("auth_token", "");
            server.setAuth_token(authToken);
            if (authToken.isBlank()) {
                logger.warn("OPA secret for '{}' has no auth_token. Available keys: {}",
                        connectorName, flat.keySet());
            }
            server.setBase_url(flat.optString("base_url", ""));
            server.setTenant_id(flat.optString("tenant_id", ""));
            server.setClient_id(flat.optString("client_id", ""));
            server.setClient_secret(flat.optString("client_secret", ""));
            server.setPassword_strategy(flat.optString("password_strategy", "standard"));

            server.setList_users_path(flat.optString("list_users_path", ""));
            server.setGet_user_path(flat.optString("get_user_path", ""));
            server.setCreate_user_path(flat.optString("create_user_path", ""));
            server.setUpdate_user_path(flat.optString("update_user_path", ""));
            server.setList_groups_path(flat.optString("list_groups_path", ""));
            server.setDelete_group_path(flat.optString("delete_group_path", ""));

            server.setConnect_timeout_ms(flat.optInt("connect_timeout_ms", 10000));
            server.setRead_timeout_ms(flat.optInt("read_timeout_ms", 10000));
            server.setWrite_timeout_ms(flat.optInt("write_timeout_ms", 10000));

            // OPA metadata (kept for reference / System Log future use)
            server.setTeam_name(flat.optString("team_name", ""));
            server.setOpa_base_url(flat.optString("opa_base_url", ""));
            server.setProjectId(flat.optString("projectId", ""));
            server.setResourceId(flat.optString("resourceId", ""));
            server.setScrtId(flat.optString("scrtId", ""));

            return server;
        } catch (Exception e) {
            logger.error("Failed to parse server from OPA secret: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Resolves the local-file config path using the precedence:
     *   1. Env var named by connector.rest.config.env-var (default: CONNECTOR_REST_CONFIG_PATH)
     *   2. Spring property connector.rest.config.path
     *   3. Spring property connector.rest.config.default-path (Docker secret mount)
     */
    private String getConfigPath() {
        String envConfigKey      = (envConfigPath != null && !envConfigPath.isBlank())
                ? envConfigPath : FALLBACK_ENV_CONFIG_PATH;
        String resolvedDefault   = (defaultConfigPath != null && !defaultConfigPath.isBlank())
                ? defaultConfigPath : FALLBACK_DEFAULT_CONFIG_PATH;

        String envPath = System.getenv(envConfigKey);
        if (envPath != null && !envPath.isBlank()) {
            return envPath;
        }
        if (configPathProperty != null && !configPathProperty.isBlank()) {
            return configPathProperty;
        }
        return resolvedDefault;
    }
}
