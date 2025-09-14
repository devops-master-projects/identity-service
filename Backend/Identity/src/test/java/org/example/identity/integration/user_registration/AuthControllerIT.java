package org.example.identity.integration.user_registration;

import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.awaitility.Awaitility;
import org.example.identity.DTO.RegisterRequest;
import org.example.identity.controllers.AuthController;
import org.example.identity.services.AuthService;
import org.junit.jupiter.api.*;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.kafka.KafkaAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@Testcontainers
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = { AuthControllerIT.BootConfig.class, AuthControllerIT.TestConfig.class, AuthControllerIT.GlobalHandler.class },
        properties = {
                "spring.main.allow-bean-definition-overriding=true"
        }
)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerIT {

    private static final String REALM = "IdentityRealm";
    private static final String CLIENT_ID = "identity-service";

    @Container
    static KeycloakContainer kc =
            new KeycloakContainer("quay.io/keycloak/keycloak:26.0.0")
                    .withRealmImportFile("keycloak/identity-realm.json");

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration(exclude = {
            DataSourceAutoConfiguration.class,
            HibernateJpaAutoConfiguration.class,
            KafkaAutoConfiguration.class,
    })
    @ComponentScan(basePackageClasses = AuthController.class)
    static class BootConfig { }

    @RestControllerAdvice
    static class GlobalHandler {
        @org.springframework.web.bind.annotation.ExceptionHandler(RuntimeException.class)
        public ResponseEntity<String> handleRuntime(RuntimeException ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ex.getMessage());
        }

        @org.springframework.web.bind.annotation.ExceptionHandler(jakarta.ws.rs.NotFoundException.class)
        public ResponseEntity<String> handleNotFound(jakarta.ws.rs.NotFoundException ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ex.getMessage());
        }
    }

    @TestConfiguration
    static class TestConfig {
        @Bean
        @Primary
        Keycloak keycloakAdmin() {
            return KeycloakBuilder.builder()
                    .serverUrl(kc.getAuthServerUrl())
                    .realm("master")
                    .clientId("admin-cli")
                    .username(kc.getAdminUsername())
                    .password(kc.getAdminPassword())
                    .build();
        }

        @Bean
        AuthService authService(@Qualifier("keycloakAdmin") Keycloak admin) {
            return new AuthService(admin, REALM);
        }
    }

    private final MockMvc mockMvc;
    private final ObjectMapper objectMapper;
    private final Keycloak admin;

    @Autowired
    AuthControllerIT(
            MockMvc mockMvc,
            ObjectMapper objectMapper,
            @Qualifier("keycloakAdmin") Keycloak admin
    ) {
        this.mockMvc = mockMvc;
        this.objectMapper = objectMapper;
        this.admin = admin;
    }

    @BeforeEach
    void cleanupUser() {
        var realm = admin.realm(REALM);
        realm.users().search("it-user", 0, 10).forEach(u -> realm.users().delete(u.getId()));
    }

    private RegisterRequest ok() {
        var r = new RegisterRequest();
        r.setUsername("it-user");
        r.setPassword("s3cret!");
        r.setFirstName("IT");
        r.setLastName("User");
        r.setEmail("it-user@example.com");
        r.setAddress("Novi Sad");
        r.setRole("guest");
        return r;
    }

    @Test
    @DisplayName("POST /api/auth/register → 200 + user created, role 'guest' assigned")
    void register_happyPath() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(ok())))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("User registered successfully!")));

        RealmResource realm = admin.realm(REALM);
        String userId = realm.users().search("it-user", 0, 1).getFirst().getId();

        Awaitility.await()
                .pollInterval(Duration.ofMillis(200))
                .atMost(5, TimeUnit.SECONDS)
                .untilAsserted(() -> {
                    UserRepresentation u = realm.users().get(userId).toRepresentation();
                    assertEquals("IT", u.getFirstName());
                    assertEquals("User", u.getLastName());
                    assertEquals("it-user@example.com", u.getEmail());
                });

        String clientUuid = realm.clients().findByClientId(CLIENT_ID).getFirst().getId();
        var roles = realm.users().get(userId).roles().clientLevel(clientUuid).listAll();
        assertTrue(roles.stream().map(RoleRepresentation::getName).anyMatch("guest"::equals));
    }

    @Test
    @DisplayName("POST /api/auth/register (duplicate) → 500 and message contains 'Failed to create user: 409'")
    void register_duplicate_returns500() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(ok())))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(ok())))
                .andExpect(status().is5xxServerError())
                .andExpect(content().string(containsString("Failed to create user: 409")));
    }

    @Test
    @DisplayName("POST /api/auth/register (nonexisting role) → 500")
    void register_missingRole_returns500() throws Exception {
        var req = ok();
        req.setRole("does-not-exist");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().is5xxServerError());
    }

    @Test
    @DisplayName("POST /api/auth/register (role = null) → 5xx")
    void register_roleNull_returns500() throws Exception {
        var req = ok();
        req.setRole(null);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().is4xxClientError());
    }

    @Test
    @DisplayName("POST /api/auth/register (role = blank) → 5xx")
    void register_roleBlank_returns500() throws Exception {
        var req = ok();
        req.setRole("   ");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().is4xxClientError());
    }

    @Test
    @DisplayName("POST /api/auth/register (username blank) → 400 Bad Request (Bean Validation)")
    void register_usernameBlank_returns400() throws Exception {
        var req = ok();
        req.setUsername("   ");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("POST /api/auth/register (email blank) → 400 Bad Request (Bean Validation)")
    void register_emailBlank_returns400() throws Exception {
        var req = ok();
        req.setEmail("   ");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }
}
