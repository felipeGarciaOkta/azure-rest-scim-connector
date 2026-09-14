package com.okta.webservice.config;

import com.okta.webservice.utils.OktaOpaExplorerBridge;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.lang.reflect.UndeclaredThrowableException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConnectorRestConfigLoaderTest {

    @TempDir
    Path tempDir;

    @Test
    void loadConfigUsesLocalFileFallback() throws Exception {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        Path config = tempDir.resolve("okta-config.json");
        Files.writeString(config, """
                {"servers":[{"name":"app","auth_token":"token","base_url":"https://example.test"}]}
                """);

        ReflectionTestUtils.setField(loader, "configPathProperty", config.toString());
        ReflectionTestUtils.setField(loader, "defaultConfigPath", tempDir.resolve("missing.json").toString());
        ReflectionTestUtils.setField(loader, "envConfigPath", "UNSET_ENV_PATH");

        ConnectorRestConfig loaded = loader.loadConfig();

        assertNotNull(loaded);
        assertEquals(1, loaded.getServers().size());
        assertEquals("app", loaded.getServers().get(0).getName());
    }

    @Test
    void getConfigReturnsCachedConfigWithoutReloading() throws Exception {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        ConnectorRestConfig expected = new ConnectorRestConfig(List.of(new ConnectorRestServerConfig()));
        ReflectionTestUtils.setField(loader, "cachedConfig", expected);
        // Prevent refreshOpaIfExpired() from treating the cache as stale when
        // REST_CONNECTOR_NAME happens to be set in the ambient environment
        // (e.g. this CI runner) -- without this the TTL check sees an elapsed
        // time of "since epoch" and triggers a real OPA reload, replacing
        // `expected` with a freshly loaded (different identity) config.
        ReflectionTestUtils.setField(loader, "lastOpaLoadTime", Instant.now());

        assertEquals(expected, loader.getConfig());
    }

    @Test
    void initCacheSwallowsStartupFailure() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        ReflectionTestUtils.setField(loader, "configPathProperty", tempDir.resolve("missing.json").toString());
        ReflectionTestUtils.setField(loader, "defaultConfigPath", tempDir.resolve("missing.json").toString());
        ReflectionTestUtils.setField(loader, "envConfigPath", "UNSET_ENV_PATH");

        assertDoesNotThrow(loader::initCache);
    }

    @Test
    void clearCacheResetsCacheAndTimestamp() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        ReflectionTestUtils.setField(loader, "cachedConfig", new ConnectorRestConfig(List.of(new ConnectorRestServerConfig())));
        ReflectionTestUtils.setField(loader, "lastOpaLoadTime", Instant.now());

        loader.clearCache();

        assertEquals(null, ReflectionTestUtils.getField(loader, "cachedConfig"));
        assertEquals(Instant.EPOCH, ReflectionTestUtils.getField(loader, "lastOpaLoadTime"));
    }

    @Test
    void forceRefreshFallsBackToClearingCacheWhenNoOpaNamesResolved() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        ReflectionTestUtils.setField(loader, "cachedConfig", new ConnectorRestConfig(List.of(new ConnectorRestServerConfig())));

        // forceRefreshFromOpa() reads REST_CONNECTOR_NAME straight from the real
        // environment. When that variable happens to be set (e.g. this CI runner),
        // it resolves a real connector name and OktaOpaExplorerBridge succeeds via
        // its bundled fallback resources, leaving a real (non-null) config cached
        // instead of clearing it. Mocking the bridge to fail makes the outcome --
        // cache ends up empty -- deterministic regardless of the ambient env.
        try (MockedStatic<OktaOpaExplorerBridge> bridge = Mockito.mockStatic(OktaOpaExplorerBridge.class)) {
            bridge.when(() -> OktaOpaExplorerBridge.retrieveConnectorConfiguration(Mockito.anyString()))
                    .thenReturn(null);

            assertDoesNotThrow(loader::forceRefreshFromOpa);
        }

        assertEquals(null, ReflectionTestUtils.getField(loader, "cachedConfig"));
    }

    @Test
    void loadConfigFromOpaCachesParsedServers() throws Exception {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        JSONObject secret = new JSONObject("""
                {"servers":[{"name":"app-one","auth_token":"token-1","base_url":"https://one.test"}]}
                """);

        try (MockedStatic<OktaOpaExplorerBridge> bridge = Mockito.mockStatic(OktaOpaExplorerBridge.class)) {
            bridge.when(() -> OktaOpaExplorerBridge.retrieveConnectorConfiguration("connector-azure"))
                    .thenReturn(secret);

            ReflectionTestUtils.invokeMethod(loader, "loadConfigFromOpa", List.of("connector-azure"));
        }

        ConnectorRestConfig cached = (ConnectorRestConfig) ReflectionTestUtils.getField(loader, "cachedConfig");
        assertNotNull(cached);
        assertEquals(1, cached.getServers().size());
        assertEquals("app-one", cached.getServers().get(0).getName());
        assertNotEquals(Instant.EPOCH, ReflectionTestUtils.getField(loader, "lastOpaLoadTime"));
    }

    @Test
    void httpGetReturnsBodyForSuccessResponse() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
            server.createContext("/ok", exchange -> respond(exchange, 200, "{\"name\":\"alpha\"}"));
            server.start();

            String body = ReflectionTestUtils.invokeMethod(loader, "httpGet",
                    "http://localhost:" + server.getAddress().getPort() + "/ok", "service-token");

            assertEquals("{\"name\":\"alpha\"}", body);
            server.stop(0);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void httpGetThrowsForErrorResponse() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
            server.createContext("/bad", exchange -> respond(exchange, 500, "failure"));
            server.start();

                UndeclaredThrowableException ex = assertThrows(UndeclaredThrowableException.class, () -> ReflectionTestUtils.invokeMethod(loader, "httpGet",
                    "http://localhost:" + server.getAddress().getPort() + "/bad", "service-token"));

                assertInstanceOf(IOException.class, ex.getUndeclaredThrowable());
                assertTrue(ex.getUndeclaredThrowable().getMessage().contains("HTTP 500"));
            server.stop(0);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void resolveConnectorNamesSplitsCommaSeparatedListAndRemovesBlanks() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();

        @SuppressWarnings("unchecked")
        List<String> names = (List<String>) ReflectionTestUtils.invokeMethod(loader,
                "resolveConnectorNames", " app-one , , app-two,app-one ");

        assertEquals(List.of("app-one", "app-two"), names);
    }

    @Test
    void extractSecretNamesCollectsNestedNamesFromObjectTree() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        String response = """
                {"items":[{"name":"alpha"},{"secret_name":"beta"}],"nested":{"secretId":"gamma","scrtId":"delta"}}
                """;

        @SuppressWarnings("unchecked")
        List<String> names = (List<String>) ReflectionTestUtils.invokeMethod(loader,
                "extractSecretNames", response);

        assertEquals(List.of("alpha", "beta", "gamma", "delta"), names);
    }

    @Test
    void extractSecretNamesHandlesBlankResponse() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();

        @SuppressWarnings("unchecked")
        List<String> names = (List<String>) ReflectionTestUtils.invokeMethod(loader,
                "extractSecretNames", "   ");

        assertTrue(names.isEmpty());
    }

    @Test
    void parseServersFromOpaSecretHandlesFlatSecretAndDefaults() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        JSONObject secret = new JSONObject()
                .put("auth_token", "token")
                .put("base_url", "https://example.test")
                .put("tenant_id", "tenant")
                .put("client_id", "client")
                .put("client_secret", "secret");

        @SuppressWarnings("unchecked")
        List<ConnectorRestServerConfig> servers = (List<ConnectorRestServerConfig>) ReflectionTestUtils.invokeMethod(
                loader, "parseServersFromOpaSecret", secret, "connector-azure");

        assertEquals(1, servers.size());
        assertEquals("connector-azure", servers.get(0).getName());
        assertEquals("token", servers.get(0).getAuth_token());
        assertEquals("standard", servers.get(0).getPassword_strategy());
        assertEquals("tenant", servers.get(0).getTenant_id());
    }

    @Test
    void parseServersFromOpaSecretHandlesServersArray() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        JSONObject secret = new JSONObject("""
                {
                  "servers": [
                    {"name":"app-one","auth_token":"token-1","base_url":"https://one.test"},
                    {"name":"app-two","auth_token":"token-2","base_url":"https://two.test"}
                  ]
                }
                """);

        @SuppressWarnings("unchecked")
        List<ConnectorRestServerConfig> servers = (List<ConnectorRestServerConfig>) ReflectionTestUtils.invokeMethod(
                loader, "parseServersFromOpaSecret", secret, "connector-azure");

        assertEquals(2, servers.size());
        assertEquals(List.of("app-one", "app-two"),
                servers.stream().map(ConnectorRestServerConfig::getName).toList());
    }

    @Test
    void parseServersFromOpaSecretReturnsEmptyListForEmptyServersArray() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        JSONObject secret = new JSONObject().put("servers", List.of());

        @SuppressWarnings("unchecked")
        List<ConnectorRestServerConfig> servers = (List<ConnectorRestServerConfig>) ReflectionTestUtils.invokeMethod(
                loader, "parseServersFromOpaSecret", secret, "connector-azure");

        assertTrue(servers.isEmpty());
    }

    @Test
    void parseServersFromOpaSecretFallsBackToEmptyListOnMalformedServersValue() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        JSONObject secret = new JSONObject().put("servers", "not-an-array");

        @SuppressWarnings("unchecked")
        List<ConnectorRestServerConfig> servers = (List<ConnectorRestServerConfig>) ReflectionTestUtils.invokeMethod(
                loader, "parseServersFromOpaSecret", secret, "connector-azure");

        assertTrue(servers.isEmpty());
    }

    @Test
    void mapServerFromFlatSecretPreservesBlankAuthToken() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        JSONObject secret = new JSONObject().put("name", "app").put("base_url", "https://example.test");

        ConnectorRestServerConfig server = ReflectionTestUtils.invokeMethod(loader,
                "mapServerFromFlatSecret", secret, "connector-azure");

        assertNotNull(server);
        assertEquals("", server.getAuth_token());
    }

    @Test
    void firstNonBlankReturnsFirstMatchingProperty() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        Properties props = new Properties();
        props.setProperty("second", "value");

        String value = ReflectionTestUtils.invokeMethod(loader, "firstNonBlank", props, new String[]{"first", "second"});

        assertEquals("value", value);
    }

    @Test
    void getConfigPathUsesPropertyWhenEnvUnavailable() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        ReflectionTestUtils.setField(loader, "envConfigPath", "UNSET_ENV_PATH");
        ReflectionTestUtils.setField(loader, "configPathProperty", "/tmp/from-property.json");
        ReflectionTestUtils.setField(loader, "defaultConfigPath", "/tmp/default.json");

        String path = ReflectionTestUtils.invokeMethod(loader, "getConfigPath");

        assertEquals("/tmp/from-property.json", path);
    }

    @Test
    void getConfigPathFallsBackToDefaultPath() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        ReflectionTestUtils.setField(loader, "envConfigPath", "UNSET_ENV_PATH");
        ReflectionTestUtils.setField(loader, "configPathProperty", " ");
        ReflectionTestUtils.setField(loader, "defaultConfigPath", "/tmp/default.json");

        String path = ReflectionTestUtils.invokeMethod(loader, "getConfigPath");

        assertEquals("/tmp/default.json", path);
    }

    @Test
    void loadConfigRejectsInvalidLocalFile() throws Exception {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        Path config = tempDir.resolve("bad-config.json");
        Files.writeString(config, "{\"servers\":[{\"name\":\"app\",\"auth_token\":\"token\"}]}");
        ReflectionTestUtils.setField(loader, "configPathProperty", config.toString());
        ReflectionTestUtils.setField(loader, "defaultConfigPath", config.toString());
        ReflectionTestUtils.setField(loader, "envConfigPath", "UNSET_ENV_PATH");

        IOException ex = org.junit.jupiter.api.Assertions.assertThrows(IOException.class, loader::loadConfig);
        assertTrue(ex.getMessage().contains("Configuration is invalid"));
    }

    private static void respond(HttpExchange exchange, int code, String body) throws IOException {
        byte[] bytes = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(code, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }
}