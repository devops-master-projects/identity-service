package org.example.identity.integration.user_login;

import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.example.identity.DTO.LoginRequest;
import org.example.identity.DTO.RegisterRequest;
import org.example.identity.controllers.AuthController;
import org.example.identity.services.AuthService;
import org.junit.jupiter.api.*;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
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
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@Testcontainers
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = { AuthControllerLoginIT.BootConfig.class, AuthControllerLoginIT.TestConfig.class, AuthControllerLoginIT.GlobalHandler.class },
        properties = {
                "spring.main.allow-bean-definition-overriding=true"
        }
)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerLoginIT {

    private static final String REALM = "IdentityRealm";
    private static final String CLIENT_ID = "identity-service";
    private static final String CLIENT_SECRET = "test-secret-123";
    private static final String TEST_USERNAME = "it-login-user";
    private static final String TEST_PASSWORD = "s3cret!";

    @Container
    static KeycloakContainer kc =
            new KeycloakContainer("quay.io/keycloak/keycloak:26.0.0")
                    .withRealmImportFile("keycloak/identity-realm-with-secret.json");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("keycloak.server-url", kc::getAuthServerUrl);  // Changed from server.url to server-url
        registry.add("keycloak.client-id", () -> CLIENT_ID);        // Changed from client.id to client-id
        registry.add("keycloak.client-secret", () -> CLIENT_SECRET); // Changed from client.secret to client-secret
    }

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

        @org.springframework.web.bind.annotation.ExceptionHandler(org.springframework.web.client.RestClientException.class)
        public ResponseEntity<String> handleRestClient(org.springframework.web.client.RestClientException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Authentication failed: " + ex.getMessage());
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
        @Primary
        AuthService authService(@Qualifier("keycloakAdmin") Keycloak admin) {
            return new AuthService(admin, REALM);
        }
    }

    private final MockMvc mockMvc;
    private final ObjectMapper objectMapper;
    private final Keycloak admin;
    private final AuthService authService;

    @Autowired
    AuthControllerLoginIT(
            MockMvc mockMvc,
            ObjectMapper objectMapper,
            @Qualifier("keycloakAdmin") Keycloak admin,
            AuthService authService
    ) {
        this.mockMvc = mockMvc;
        this.objectMapper = objectMapper;
        this.admin = admin;
        this.authService = authService;
    }

    @BeforeEach
    void setupTestUser() {
        // Clean up and create test user
        cleanupTestUser();
        createTestUser();
    }

    @AfterEach
    void tearDown() {
        cleanupTestUser();
    }

    private void cleanupTestUser() {
        RealmResource realm = admin.realm(REALM);
        realm.users().search(TEST_USERNAME, 0, 10)
                .forEach(u -> realm.users().delete(u.getId()));
    }

    private void createTestUser() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setUsername(TEST_USERNAME);
        registerRequest.setPassword(TEST_PASSWORD);
        registerRequest.setFirstName("IT");
        registerRequest.setLastName("LoginUser");
        registerRequest.setEmail("it-login-user@example.com");
        registerRequest.setAddress("Novi Sad");
        registerRequest.setRole("guest");

        try {
            authService.register(registerRequest);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create test user", e);
        }
    }

    private LoginRequest validLoginRequest() {
        LoginRequest request = new LoginRequest();
        request.setUsername(TEST_USERNAME);
        request.setPassword(TEST_PASSWORD);
        return request;
    }

    @Test
    @DisplayName("POST /api/auth/login → 200 + valid token response")
    void login_happyPath() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validLoginRequest())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").exists())
                .andExpect(jsonPath("$.refresh_token").exists());
    }

    @Test
    @DisplayName("POST /api/auth/login (invalid password) → 401 Unauthorized")
    void login_invalidPassword_returns401() throws Exception {
        LoginRequest request = validLoginRequest();
        request.setPassword("wrong-password");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(containsString("Authentication failed")));
    }

    @Test
    @DisplayName("POST /api/auth/login (non-existent user) → 401 Unauthorized")
    void login_nonExistentUser_returns401() throws Exception {
        LoginRequest request = new LoginRequest();
        request.setUsername("non-existent-user");
        request.setPassword("any-password");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(containsString("Authentication failed")));
    }

    @Test
    @DisplayName("POST /api/auth/login (null username) → 401 Unauthorized")
    void login_nullUsername_returns401() throws Exception {
        LoginRequest request = new LoginRequest();
        request.setUsername(null);
        request.setPassword(TEST_PASSWORD);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("POST /api/auth/login (empty username) → 401 Unauthorized")
    void login_emptyUsername_returns401() throws Exception {
        LoginRequest request = new LoginRequest();
        request.setUsername("");
        request.setPassword(TEST_PASSWORD);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("POST /api/auth/login (null password) → 401 Unauthorized")
    void login_nullPassword_returns401() throws Exception {
        LoginRequest request = new LoginRequest();
        request.setUsername(TEST_USERNAME);
        request.setPassword(null);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("POST /api/auth/login (empty password) → 401 Unauthorized")
    void login_emptyPassword_returns401() throws Exception {
        LoginRequest request = new LoginRequest();
        request.setUsername(TEST_USERNAME);
        request.setPassword("");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("POST /api/auth/login (disabled user) → 401 Unauthorized")
    void login_disabledUser_returns401() throws Exception {
        // Disable the user
        RealmResource realm = admin.realm(REALM);
        UserRepresentation user = realm.users().search(TEST_USERNAME, 0, 1).getFirst();
        user.setEnabled(false);
        realm.users().get(user.getId()).update(user);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validLoginRequest())))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(containsString("Authentication failed")));
    }

    @Test
    @DisplayName("POST /api/auth/login (case insensitive username) → 200 OK")
    void login_caseInsensitiveUsername_returns200() throws Exception {
        LoginRequest request = validLoginRequest();
        request.setUsername(TEST_USERNAME.toUpperCase());

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.token_type").value("Bearer"));
    }

    @Test
    @DisplayName("POST /api/auth/login (missing Content-Type) → 415 Unsupported Media Type")
    void login_missingContentType_returns415() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .content(objectMapper.writeValueAsString(validLoginRequest())))
                .andExpect(status().isUnsupportedMediaType());
    }
}