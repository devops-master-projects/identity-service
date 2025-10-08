package org.example.identity.integration.user_login;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.example.identity.DTO.LoginRequest;
import org.example.identity.DTO.RegisterRequest;
import org.example.identity.services.AuthService;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import static org.mockito.ArgumentMatchers.*;


@Testcontainers
class AuthServiceIT {

    private static final String REALM = "IdentityRealm";
    private static final String CLIENT_ID = "identity-service";
    private static final String TEST_USERNAME = "it-login-user";
    private static final String TEST_PASSWORD = "s3cret!";

    @Container
    static KeycloakContainer kc =
            new KeycloakContainer("quay.io/keycloak/keycloak:26.0.0")
                    .withRealmImportFile("keycloak/identity-realm.json");

    Keycloak admin;
    AuthService auth;
    RestTemplate template;


    @BeforeEach
    void setUp() throws Exception {
        admin = KeycloakBuilder.builder()
                .serverUrl(kc.getAuthServerUrl())
                .realm("master")
                .clientId("admin-cli")
                .username(kc.getAdminUsername())
                .password(kc.getAdminPassword())
                .build();

        template = mock(RestTemplate.class);
        auth = new AuthService(admin, REALM, template);

        setPrivateField("keycloakServerUrl", kc.getAuthServerUrl());
        setPrivateField("clientId", CLIENT_ID);
        setPrivateField("clientSecret", "your-client-secret-from-keycloak");

        cleanupTestUser();
        createTestUser();
    }

    @AfterEach
    void tearDown() {
        cleanupTestUser();
    }

    private void setPrivateField(String fieldName, String value) throws Exception {
        Field field = AuthService.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(auth, value);
    }

    private void cleanupTestUser() {
        var realm = admin.realm(REALM);
        realm.users().search(TEST_USERNAME, 0, 10)
                .forEach(u -> realm.users().delete(u.getId()));
    }

    private void createTestUser() {
        var registerRequest = new RegisterRequest();
        registerRequest.setUsername(TEST_USERNAME);
        registerRequest.setPassword(TEST_PASSWORD);
        registerRequest.setFirstName("IT");
        registerRequest.setLastName("LoginUser");
        registerRequest.setEmail("it-login-user@example.com");
        registerRequest.setAddress("Novi Sad");
        registerRequest.setRole("guest");

        assertDoesNotThrow(() -> auth.register(registerRequest));
    }

    private LoginRequest validLoginRequest() {
        LoginRequest request = new LoginRequest();
        request.setUsername(TEST_USERNAME);
        request.setPassword(TEST_PASSWORD);
        return request;
    }

    @Test
    @DisplayName("login: happy path - valid credentials return access token")
    void login_happyPath() {
        LoginRequest request = validLoginRequest();

        Map<String, Object> result = assertDoesNotThrow(() -> auth.login(request));

        assertNotNull(result);
        assertTrue(result.containsKey("access_token"));
        assertTrue(result.containsKey("token_type"));
        assertTrue(result.containsKey("expires_in"));

        String accessToken = (String) result.get("access_token");
        assertNotNull(accessToken);
        assertFalse(accessToken.isEmpty());

        assertEquals("Bearer", result.get("token_type"));

        Integer expiresIn = (Integer) result.get("expires_in");
        assertNotNull(expiresIn);
        assertTrue(expiresIn > 0);
    }

    @Test
    @DisplayName("login: invalid password - throws RestClientException")
    void login_invalidPassword_throws() {
        LoginRequest request = validLoginRequest();
        request.setPassword("wrong-password");

        assertThrows(RestClientException.class, () -> auth.login(request));
    }

    @Test
    @DisplayName("login: non-existent user - throws RestClientException")
    void login_nonExistentUser_throws() {
        LoginRequest request = new LoginRequest();
        request.setUsername("non-existent-user");
        request.setPassword("any-password");

        assertThrows(RestClientException.class, () -> auth.login(request));
    }

    @ParameterizedTest(name = "username=\"{0}\" - throws RestClientException")
    @NullAndEmptySource
    @ValueSource(strings = {" ", "   "})
    @DisplayName("login: blank/null username - throws RestClientException")
    void login_blankUsername_throws(String username) {
        LoginRequest request = new LoginRequest();
        request.setUsername(username);
        request.setPassword(TEST_PASSWORD);

        assertThrows(RestClientException.class, () -> auth.login(request));
    }

    @ParameterizedTest(name = "password=\"{0}\" - throws RestClientException")
    @NullAndEmptySource
    @ValueSource(strings = {" ", "   "})
    @DisplayName("login: blank/null password - throws RestClientException")
    void login_blankPassword_throws(String password) {
        LoginRequest request = new LoginRequest();
        request.setUsername(TEST_USERNAME);
        request.setPassword(password);

        assertThrows(RestClientException.class, () -> auth.login(request));
    }

    @Test
    @DisplayName("login: disabled user - throws RestClientException")
    void login_disabledUser_throws() {
        RealmResource realm = admin.realm(REALM);
        var users = realm.users().search(TEST_USERNAME, 0, 1);
        var user = users.getFirst();
        user.setEnabled(false);
        realm.users().get(user.getId()).update(user);

        LoginRequest request = validLoginRequest();

        assertThrows(RestClientException.class, () -> auth.login(request));
    }

    @Test
    @DisplayName("login: successful login contains refresh token")
    void login_successContainsRefreshToken() {
        LoginRequest request = validLoginRequest();

        Map<String, Object> result = assertDoesNotThrow(() -> auth.login(request));

        assertNotNull(result);
        assertTrue(result.containsKey("refresh_token"));

        String refreshToken = (String) result.get("refresh_token");
        assertNotNull(refreshToken);
        assertFalse(refreshToken.isEmpty());
    }

    @Test
    @DisplayName("login: token response contains scope")
    void login_tokenResponseContainsScope() {
        LoginRequest request = validLoginRequest();

        Map<String, Object> result = assertDoesNotThrow(() -> auth.login(request));

        assertNotNull(result);
        assertTrue(result.containsKey("scope"));

        String scope = (String) result.get("scope");
        assertNotNull(scope);
        assertTrue(scope.contains("openid") || scope.contains("profile"));
    }

    @Test
    @DisplayName("login: multiple successful logins work")
    void login_multipleSuccessfulLogins() {
        LoginRequest request = validLoginRequest();

        Map<String, Object> result1 = assertDoesNotThrow(() -> auth.login(request));
        assertNotNull(result1);
        assertTrue(result1.containsKey("access_token"));

        Map<String, Object> result2 = assertDoesNotThrow(() -> auth.login(request));
        assertNotNull(result2);
        assertTrue(result2.containsKey("access_token"));

        assertNotEquals(result1.get("access_token"), result2.get("access_token"));
    }

    @Test
    @DisplayName("login: case insensitive username - Keycloak accepts uppercase")
    void login_caseInsensitiveUsername() {
        LoginRequest request = new LoginRequest();
        request.setUsername(TEST_USERNAME.toUpperCase());
        request.setPassword(TEST_PASSWORD);

        Map<String, Object> result = assertDoesNotThrow(() -> auth.login(request));

        assertNotNull(result);
        assertTrue(result.containsKey("access_token"));
        assertTrue(result.containsKey("token_type"));
    }

    @Test
    @DisplayName("deleteAccount: host can delete account and Keycloak user is removed")
    void deleteAccount_happyPath() {
        var register = new RegisterRequest();
        register.setUsername("host-delete");
        register.setPassword("test123!");
        register.setFirstName("Host");
        register.setLastName("Delete");
        register.setEmail("host-delete@example.com");
        register.setRole("host");
        register.setAddress("Novi Sad");
        auth.register(register);

        var userId = auth.getUserIdFromUsername("host-delete");
        assertNotNull(userId);

        when(template.exchange(
                contains("/host/can-delete-account"),
                eq(HttpMethod.GET),
                any(),
                eq(Boolean.class)
        )).thenReturn(new ResponseEntity<>(true, HttpStatus.OK));

        when(template.exchange(
                contains("/api/accommodations/host/all"),
                eq(HttpMethod.DELETE),
                any(),
                eq(Void.class)
        )).thenReturn(new ResponseEntity<>(HttpStatus.NO_CONTENT));

        Jwt jwt = Jwt.withTokenValue("fake-token")
                .claim("sub", userId)
                .claim("resource_access", Map.of(
                        "identity-service", Map.of("roles", List.of("host"))
                ))
                .header("alg", "none")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();

        var authentication = mock(org.springframework.security.core.Authentication.class);
        when(authentication.getPrincipal()).thenReturn(jwt);

        assertDoesNotThrow(() -> auth.deleteAccount(authentication));

        var remaining = admin.realm(REALM).users().search("host-delete", 0, 5);
        assertTrue(remaining.isEmpty(), "User should be deleted from Keycloak");
    }

}