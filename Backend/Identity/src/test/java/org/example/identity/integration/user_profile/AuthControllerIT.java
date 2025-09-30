package org.example.identity.integration.user_profile;

import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.example.identity.DTO.ChangeCredentialsRequest;
import org.example.identity.DTO.LoginRequest;
import org.example.identity.DTO.RegisterRequest;
import org.example.identity.DTO.UpdateProfileRequest;
import org.example.identity.controllers.AuthController;
import org.example.identity.services.AuthService;
import org.junit.jupiter.api.*;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
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
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.RestTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Map;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@Testcontainers
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = { AuthControllerProfileIT.BootConfig.class, AuthControllerProfileIT.TestConfig.class, AuthControllerProfileIT.GlobalHandler.class },
        properties = {
                "spring.main.allow-bean-definition-overriding=true"
        }
)
@AutoConfigureMockMvc
class AuthControllerProfileIT {

    private static final String REALM = "IdentityRealm";
    private static final String CLIENT_ID = "identity-service";
    private static final String CLIENT_SECRET = "test-secret-123";
    private static final String TEST_USERNAME = "it-profile-user";
    private static final String TEST_PASSWORD = "s3cret!";

    @Container
    static KeycloakContainer kc =
            new KeycloakContainer("quay.io/keycloak/keycloak:26.0.0")
                    .withRealmImportFile("keycloak/identity-realm-with-secret.json");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("keycloak.server-url", kc::getAuthServerUrl);
        registry.add("keycloak.client-id", () -> CLIENT_ID);
        registry.add("keycloak.client-secret", () -> CLIENT_SECRET);
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
            return new AuthService(admin, REALM, new RestTemplate());
        }
    }

    private final MockMvc mockMvc;
    private final ObjectMapper objectMapper;
    private final Keycloak admin;
    private final AuthService authService;
    private String testUserId;

    @Autowired
    AuthControllerProfileIT(
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
    void setup() throws Exception {
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
        registerRequest.setFirstName("John");
        registerRequest.setLastName("Doe");
        registerRequest.setEmail("john.doe@example.com");
        registerRequest.setAddress("Belgrade");
        registerRequest.setRole("guest");

        try {
            authService.register(registerRequest);
            testUserId = authService.getUserIdFromUsername(TEST_USERNAME);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create test user", e);
        }
    }

    // ===== GET /api/auth/profile Tests =====

    @Test
    @DisplayName("GET /api/auth/profile → 200 + user profile")
    @WithMockUser
    void getProfile_happyPath() throws Exception {
        mockMvc.perform(get("/api/auth/profile")
                        .with(jwt().jwt(jwt -> jwt.subject(testUserId)))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(testUserId))
                .andExpect(jsonPath("$.username").value(TEST_USERNAME))
                .andExpect(jsonPath("$.firstName").value("John"))
                .andExpect(jsonPath("$.lastName").value("Doe"))
                .andExpect(jsonPath("$.email").value("john.doe@example.com"));
    }

    @Test
    @DisplayName("GET /api/auth/profile (no authentication) → 401 Unauthorized")
    void getProfile_noAuth_returns401() throws Exception {
        mockMvc.perform(get("/api/auth/profile")
                        .with(csrf()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /api/auth/profile (invalid JWT) → 500 Internal Server Error")
    void getProfile_invalidJWT_returns500() throws Exception {
        mockMvc.perform(get("/api/auth/profile")
                        .with(jwt().jwt(jwt -> jwt.subject("invalid-user-id")))
                        .with(csrf()))
                .andExpect(status().isInternalServerError());
    }

    // ===== PUT /api/auth/profile Tests =====

    @Test
    @DisplayName("PUT /api/auth/profile → 200 + success message")
    @WithMockUser
    void updateProfile_happyPath() throws Exception {
        UpdateProfileRequest request = new UpdateProfileRequest();
        request.setFirstName("Jane");
        request.setLastName("Smith");
        request.setEmail("jane.smith@example.com");
        request.setAddress("Novi Sad");

        mockMvc.perform(put("/api/auth/profile")
                        .with(jwt().jwt(jwt -> jwt.subject(testUserId)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(content().string("Profile updated successfully!"));

        // Verify the update by checking the profile
        mockMvc.perform(get("/api/auth/profile")
                        .with(jwt().jwt(jwt -> jwt.subject(testUserId)))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.firstName").value("Jane"))
                .andExpect(jsonPath("$.lastName").value("Smith"))
                .andExpect(jsonPath("$.email").value("jane.smith@example.com"));
    }

    @Test
    @DisplayName("PUT /api/auth/profile (partial update) → 200 + success message")
    @WithMockUser
    void updateProfile_partialUpdate() throws Exception {
        UpdateProfileRequest request = new UpdateProfileRequest();
        request.setFirstName("UpdatedName");

        mockMvc.perform(put("/api/auth/profile")
                        .with(jwt().jwt(jwt -> jwt.subject(testUserId)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(content().string("Profile updated successfully!"));

        // Verify only firstName was updated
        mockMvc.perform(get("/api/auth/profile")
                        .with(jwt().jwt(jwt -> jwt.subject(testUserId)))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.firstName").value("UpdatedName"))
                .andExpect(jsonPath("$.lastName").value("Doe"))
                .andExpect(jsonPath("$.email").value("john.doe@example.com"));
    }

    @Test
    @DisplayName("PUT /api/auth/profile (no authentication) → 401 Unauthorized")
    void updateProfile_noAuth_returns401() throws Exception {
        UpdateProfileRequest request = new UpdateProfileRequest();
        request.setFirstName("Test");

        mockMvc.perform(put("/api/auth/profile")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("PUT /api/auth/profile (invalid email format) → 400 Bad Request")
    @WithMockUser
    void updateProfile_invalidEmail_returns400() throws Exception {
        UpdateProfileRequest request = new UpdateProfileRequest();
        request.setEmail("invalid-email-format");

        mockMvc.perform(put("/api/auth/profile")
                        .with(jwt().jwt(jwt -> jwt.subject(testUserId)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("PUT /api/auth/profile (empty body) → 200 + success message")
    @WithMockUser
    void updateProfile_emptyBody_returns200() throws Exception {
        UpdateProfileRequest request = new UpdateProfileRequest();

        mockMvc.perform(put("/api/auth/profile")
                        .with(jwt().jwt(jwt -> jwt.subject(testUserId)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(content().string("Profile updated successfully!"));
    }

    // ===== PUT /api/auth/credentials Tests =====

    @Test
    @DisplayName("PUT /api/auth/credentials → 200 + success message")
    @WithMockUser
    void changeCredentials_happyPath() throws Exception {
        ChangeCredentialsRequest request = new ChangeCredentialsRequest();
        request.setCurrentPassword(TEST_PASSWORD);
        request.setNewPassword("newS3cret!");

        mockMvc.perform(put("/api/auth/credentials")
                        .with(jwt().jwt(jwt -> jwt.subject(testUserId)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(content().string("Credentials updated successfully!"));

        // Verify the old password no longer works by attempting login
        LoginRequest oldPasswordLogin = new LoginRequest();
        oldPasswordLogin.setUsername(TEST_USERNAME);
        oldPasswordLogin.setPassword(TEST_PASSWORD);

        mockMvc.perform(post("/api/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(oldPasswordLogin)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("PUT /api/auth/credentials (incorrect current password) → 500 Internal Server Error")
    @WithMockUser
    void changeCredentials_incorrectCurrentPassword_returns500() throws Exception {
        ChangeCredentialsRequest request = new ChangeCredentialsRequest();
        request.setCurrentPassword("wrong-password");
        request.setNewPassword("newS3cret!");

        mockMvc.perform(put("/api/auth/credentials")
                        .with(jwt().jwt(jwt -> jwt.subject(testUserId)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isInternalServerError())
                .andExpect(content().string(containsString("Current password is incorrect")));
    }

    @Test
    @DisplayName("PUT /api/auth/credentials (no authentication) → 401 Unauthorized")
    void changeCredentials_noAuth_returns401() throws Exception {
        ChangeCredentialsRequest request = new ChangeCredentialsRequest();
        request.setCurrentPassword(TEST_PASSWORD);
        request.setNewPassword("newS3cret!");

        mockMvc.perform(put("/api/auth/credentials")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("PUT /api/auth/credentials (null current password) → 400 Bad Request")
    @WithMockUser
    void changeCredentials_nullCurrentPassword_returns400() throws Exception {
        ChangeCredentialsRequest request = new ChangeCredentialsRequest();
        request.setCurrentPassword(null);
        request.setNewPassword("newS3cret!");

        mockMvc.perform(put("/api/auth/credentials")
                        .with(jwt().jwt(jwt -> jwt.subject(testUserId)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("PUT /api/auth/credentials (null new password) → 400 Bad Request")
    @WithMockUser
    void changeCredentials_nullNewPassword_returns400() throws Exception {
        ChangeCredentialsRequest request = new ChangeCredentialsRequest();
        request.setCurrentPassword(TEST_PASSWORD);
        request.setNewPassword(null);

        mockMvc.perform(put("/api/auth/credentials")
                        .with(jwt().jwt(jwt -> jwt.subject(testUserId)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("PUT /api/auth/credentials (empty current password) → 400 Bad Request")
    @WithMockUser
    void changeCredentials_emptyCurrentPassword_returns400() throws Exception {
        ChangeCredentialsRequest request = new ChangeCredentialsRequest();
        request.setCurrentPassword("");
        request.setNewPassword("newS3cret!");

        mockMvc.perform(put("/api/auth/credentials")
                        .with(jwt().jwt(jwt -> jwt.subject(testUserId)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("PUT /api/auth/credentials (empty new password) → 400 Bad Request")
    @WithMockUser
    void changeCredentials_emptyNewPassword_returns400() throws Exception {
        ChangeCredentialsRequest request = new ChangeCredentialsRequest();
        request.setCurrentPassword(TEST_PASSWORD);
        request.setNewPassword("");

        mockMvc.perform(put("/api/auth/credentials")
                        .with(jwt().jwt(jwt -> jwt.subject(testUserId)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    // ===== Integration Tests =====

    @Test
    @DisplayName("Integration: complete profile update workflow")
    @WithMockUser
    void integration_completeProfileUpdateWorkflow() throws Exception {
        // Update profile
        UpdateProfileRequest updateRequest = new UpdateProfileRequest();
        updateRequest.setFirstName("Jane");
        updateRequest.setLastName("Smith");
        updateRequest.setEmail("jane.smith@example.com");
        updateRequest.setAddress("Kragujevac");

        mockMvc.perform(put("/api/auth/profile")
                        .with(jwt().jwt(jwt -> jwt.subject(testUserId)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(updateRequest)))
                .andExpect(status().isOk());

        // Verify changes
        mockMvc.perform(get("/api/auth/profile")
                        .with(jwt().jwt(jwt -> jwt.subject(testUserId)))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.firstName").value("Jane"))
                .andExpect(jsonPath("$.lastName").value("Smith"))
                .andExpect(jsonPath("$.email").value("jane.smith@example.com"));
    }

    @Test
    @DisplayName("Integration: profile access after credential change")
    @WithMockUser
    void integration_profileAccessAfterCredentialChange() throws Exception {
        String newPassword = "superS3cret!";

        // Change password
        ChangeCredentialsRequest changeRequest = new ChangeCredentialsRequest();
        changeRequest.setCurrentPassword(TEST_PASSWORD);
        changeRequest.setNewPassword(newPassword);

        mockMvc.perform(put("/api/auth/credentials")
                        .with(jwt().jwt(jwt -> jwt.subject(testUserId)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(changeRequest)))
                .andExpect(status().isOk());

        // Verify profile is still accessible (same JWT, different password)
        mockMvc.perform(get("/api/auth/profile")
                        .with(jwt().jwt(jwt -> jwt.subject(testUserId)))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(TEST_USERNAME));
    }
}