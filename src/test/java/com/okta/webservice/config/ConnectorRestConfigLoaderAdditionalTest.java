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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.UndeclaredThrowableException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConnectorRestConfigLoaderAdditionalTest {

    @TempDir
    Path tempDir;

    @Test
    void loadConfigFromOpaDeduplicatesServersAcrossSecrets() throws Exception {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        JSONObject first = new JSONObject("""
                {"servers":[{"name":"app-one","auth_token":"token-1"},{"name":"app-two","auth_token":"token-2"}]}
                """);
        JSONObject second = new JSONObject("""
                {"servers":[{"name":"app-two","auth_token":"token-override"},{"name":"app-three","auth_token":"token-3"}]}
                """);

        try (MockedStatic<OktaOpaExplorerBridge> bridge = Mockito.mockStatic(OktaOpaExplorerBridge.class)) {
            bridge.when(() -> OktaOpaExplorerBridge.retrieveConnectorConfiguration("one")).thenReturn(first);
            bridge.when(() -> OktaOpaExplorerBridge.retrieveConnectorConfiguration("two")).thenReturn(second);

            ReflectionTestUtils.invokeMethod(loader, "loadConfigFromOpa", List.of("one", "two"));
        }

        ConnectorRestConfig config = (ConnectorRestConfig) ReflectionTestUtils.getField(loader, "cachedConfig");
        assertNotNull(config);
        assertEquals(List.of("app-one", "app-two", "app-three"),
                config.getServers().stream().map(ConnectorRestServerConfig::getName).toList());
        assertEquals("token-override", config.getServers().get(1).getAuth_token());
    }

    @Test
    void loadConfigFromOpaThrowsWhenNoServersAreReturned() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();

        try (MockedStatic<OktaOpaExplorerBridge> bridge = Mockito.mockStatic(OktaOpaExplorerBridge.class)) {
            bridge.when(() -> OktaOpaExplorerBridge.retrieveConnectorConfiguration("missing")).thenReturn(null);

            IllegalStateException ex = assertThrows(IllegalStateException.class,
                    () -> ReflectionTestUtils.invokeMethod(loader, "loadConfigFromOpa", List.of("missing")));

            assertTrue(ex.getMessage().contains("No servers loaded from OPA"));
        }
    }

    @Test
    void loadConfigFromFileThrowsWhenFileMissing() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        ReflectionTestUtils.setField(loader, "configPathProperty", tempDir.resolve("missing.json").toString());
        ReflectionTestUtils.setField(loader, "defaultConfigPath", tempDir.resolve("missing.json").toString());
        ReflectionTestUtils.setField(loader, "envConfigPath", "UNSET_ENV_PATH");

        UndeclaredThrowableException ex = assertThrows(UndeclaredThrowableException.class,
                () -> ReflectionTestUtils.invokeMethod(loader, "loadConfigFromFile"));
        assertInstanceOf(IOException.class, ex.getUndeclaredThrowable());
    }

    @Test
    void resolveConnectorNamesFallsBackToExplicitSingleName() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();

        @SuppressWarnings("unchecked")
        List<String> names = (List<String>) ReflectionTestUtils.invokeMethod(loader,
                "resolveConnectorNames", "connector-azure");

        assertEquals(List.of("connector-azure"), names);
    }

    @Test
    void resolveConnectorNamesReturnsEmptyWhenInputBlankAndDiscoveryFails() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();

        @SuppressWarnings("unchecked")
        List<String> names = (List<String>) ReflectionTestUtils.invokeMethod(loader,
                "resolveConnectorNames", "   ");

        assertTrue(names.isEmpty());
    }

    @Test
    void extractSecretNamesHandlesArrayRoot() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();

        @SuppressWarnings("unchecked")
        List<String> names = (List<String>) ReflectionTestUtils.invokeMethod(loader,
                "extractSecretNames", "[{\"name\":\"alpha\"},{\"secret_name\":\"beta\"}]");

        assertEquals(List.of("alpha", "beta"), names);
    }

    @Test
    void collectNamesIgnoresScalarNodes() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        Set<String> names = new LinkedHashSet<>();

        ReflectionTestUtils.invokeMethod(loader, "collectNames", "plain-text", names);

        assertTrue(names.isEmpty());
    }

    @Test
    void loadBootstrapConfigReadsAlternatePropertyNames() throws Exception {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        String content = """
                opa_base_url=http://localhost
                team_name=my-team
                project.id=my-project
                resource.id=my-resource
                """;
        Path configPath = Path.of("/run/config/oktaopaapiexplorer.config");

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.newInputStream(configPath))
                    .thenReturn(new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));

            Object bootstrap = ReflectionTestUtils.invokeMethod(loader, "loadBootstrapConfig");

            assertEquals("http://localhost", ReflectionTestUtils.invokeMethod(bootstrap, "opaBaseUrl"));
            assertEquals("my-team", ReflectionTestUtils.invokeMethod(bootstrap, "teamName"));
        }
    }

    @Test
    void loadBootstrapConfigRejectsMissingValues() throws Exception {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        Path configPath = Path.of("/run/config/oktaopaapiexplorer.config");

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.newInputStream(configPath))
                    .thenReturn(new ByteArrayInputStream("opa.base.url=http://localhost\n".getBytes(StandardCharsets.UTF_8)));

            UndeclaredThrowableException ex = assertThrows(UndeclaredThrowableException.class,
                    () -> ReflectionTestUtils.invokeMethod(loader, "loadBootstrapConfig"));

            assertInstanceOf(IOException.class, ex.getUndeclaredThrowable());
        }
    }

    @Test
    void discoverConnectorNamesFromOpaSecretsReturnsParsedNames() throws Exception {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/v1/teams/my-team/resource_groups/my-resource/projects/my-project/secrets",
                exchange -> respond(exchange, 200, "{\"items\":[{\"name\":\"alpha\"},{\"name\":\"beta\"}]}"));
        server.start();
        String content = """
                opa.base.url=http://localhost:%d
                team.name=my-team
                projectId=my-project
                resourceId=my-resource
                """.formatted(server.getAddress().getPort());
        Path configPath = Path.of("/run/config/oktaopaapiexplorer.config");

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS);
             MockedStatic<OktaOpaExplorerBridge> bridge = Mockito.mockStatic(OktaOpaExplorerBridge.class)) {
            files.when(() -> Files.newInputStream(configPath))
                    .thenReturn(new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));
            bridge.when(OktaOpaExplorerBridge::getOktaOpaServiceToken).thenReturn("service-token");

            @SuppressWarnings("unchecked")
            List<String> names = (List<String>) ReflectionTestUtils.invokeMethod(loader,
                    "discoverConnectorNamesFromOpaSecrets");

            assertEquals(List.of("alpha", "beta"), names);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void discoverConnectorNamesFromOpaSecretsReturnsEmptyOnFailure() throws Exception {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        Path configPath = Path.of("/run/config/oktaopaapiexplorer.config");

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.newInputStream(configPath)).thenThrow(new IOException("missing"));

            @SuppressWarnings("unchecked")
            List<String> names = (List<String>) ReflectionTestUtils.invokeMethod(loader,
                    "discoverConnectorNamesFromOpaSecrets");

            assertTrue(names.isEmpty());
        }
    }

    @Test
    void mapServerFromFlatSecretMapsAllOptionalFields() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        JSONObject secret = new JSONObject()
                .put("name", "app")
                .put("auth_token", "token")
                .put("base_url", "https://example.test")
                .put("tenant_id", "tenant")
                .put("client_id", "client")
                .put("client_secret", "secret")
                .put("password_strategy", "concatenated")
                .put("list_users_path", "/users")
                .put("get_user_path", "/users/{id}")
                .put("create_user_path", "/users")
                .put("update_user_path", "/users/{id}")
                .put("list_groups_path", "/groups")
                .put("delete_group_path", "/groups/{id}")
                .put("connect_timeout_ms", 1500)
                .put("read_timeout_ms", 2500)
                .put("write_timeout_ms", 3500)
                .put("team_name", "team")
                .put("opa_base_url", "https://opa")
                .put("projectId", "project")
                .put("resourceId", "resource")
                .put("scrtId", "secret-id");

        ConnectorRestServerConfig server = ReflectionTestUtils.invokeMethod(loader,
                "mapServerFromFlatSecret", secret, "connector-azure");

        assertEquals("concatenated", server.getPassword_strategy());
        assertEquals(1500, server.getConnect_timeout_ms());
        assertEquals("secret-id", server.getScrtId());
    }

    @Test
    void firstNonBlankReturnsEmptyWhenNothingMatches() {
        ConnectorRestConfigLoader loader = new ConnectorRestConfigLoader();
        Properties props = new Properties();

        String value = ReflectionTestUtils.invokeMethod(loader, "firstNonBlank", props, new String[]{"a", "b"});

        assertEquals("", value);
    }

    private static void respond(HttpExchange exchange, int code, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(code, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }
}
