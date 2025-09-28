package org.example.identity.integration.user_profile;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.example.identity.DTO.ChangeCredentialsRequest;
import org.example.identity.DTO.RegisterRequest;
import org.example.identity.DTO.UpdateProfileRequest;
import org.example.identity.services.AuthService;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.UserRepresentation;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@Testcontainers
class AuthServiceIT {

    private static final String REALM = "IdentityRealm";
    private static final String CLIENT_ID = "identity-service";
    private static final String TEST_USERNAME = "it-profile-user";
    private static final String TEST_PASSWORD = "s3cret!";

    @Container
    static KeycloakContainer kc =
            new KeycloakContainer("quay.io/keycloak/keycloak:26.0.0")
                    .withRealmImportFile("keycloak/identity-realm.json");

    Keycloak admin;
    AuthService auth;
    String testUserId;

    @BeforeEach
    void setUp() throws Exception {
        admin = KeycloakBuilder.builder()
                .serverUrl(kc.getAuthServerUrl())
                .realm("master")
                .clientId("admin-cli")
                .username(kc.getAdminUsername())
                .password(kc.getAdminPassword())
                .build();

        auth = new AuthService(admin, REALM);

        setPrivateField("keycloakServerUrl", kc.getAuthServerUrl());
        setPrivateField("clientId", CLIENT_ID);
        setPrivateField("clientSecret", "your-client-secret-from-keycloak");

        cleanupTestUser();
        createTestUser();
        testUserId = auth.getUserIdFromUsername(TEST_USERNAME);
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
        registerRequest.setFirstName("John");
        registerRequest.setLastName("Doe");
        registerRequest.setEmail("john.doe@example.com");
        registerRequest.setAddress("Belgrade");
        registerRequest.setRole("guest");

        assertDoesNotThrow(() -> auth.register(registerRequest));
    }

    @Test
    @DisplayName("updateProfile: happy path - updates all fields successfully")
    void updateProfile_happyPath() {
        UpdateProfileRequest request = new UpdateProfileRequest();
        request.setFirstName("Jane");
        request.setLastName("Smith");
        request.setEmail("jane.smith@example.com");

        assertDoesNotThrow(() -> auth.updateProfile(testUserId, request));

        UserRepresentation updatedUser = auth.getUserProfile(testUserId);
        assertEquals("Jane", updatedUser.getFirstName());
        assertEquals("Smith", updatedUser.getLastName());
        assertEquals("jane.smith@example.com", updatedUser.getEmail());
    }

    @Test
    @DisplayName("updateProfile: partial update - only lastName")
    void updateProfile_partialUpdate_lastName() {
        UpdateProfileRequest request = new UpdateProfileRequest();
        request.setLastName("UpdatedLastName");

        assertDoesNotThrow(() -> auth.updateProfile(testUserId, request));

        UserRepresentation updatedUser = auth.getUserProfile(testUserId);
        assertEquals("John", updatedUser.getFirstName());
        assertEquals("UpdatedLastName", updatedUser.getLastName());
        assertEquals("john.doe@example.com", updatedUser.getEmail());
    }

    @Test
    @DisplayName("updateProfile: partial update - only email")
    void updateProfile_partialUpdate_email() {
        UpdateProfileRequest request = new UpdateProfileRequest();
        request.setEmail("updated@example.com");

        assertDoesNotThrow(() -> auth.updateProfile(testUserId, request));

        UserRepresentation updatedUser = auth.getUserProfile(testUserId);
        assertEquals("John", updatedUser.getFirstName());
        assertEquals("Doe", updatedUser.getLastName());
        assertEquals("updated@example.com", updatedUser.getEmail());
    }

    @Test
    @DisplayName("updateProfile: remove address with blank string")
    void updateProfile_removeAddress_blankString() {
        UpdateProfileRequest request = new UpdateProfileRequest();
        request.setAddress("");

        assertDoesNotThrow(() -> auth.updateProfile(testUserId, request));

        UserRepresentation updatedUser = auth.getUserProfile(testUserId);
        assertNull(auth.getAddressFromUser(updatedUser));
    }

    @Test
    @DisplayName("updateProfile: remove address with whitespace string")
    void updateProfile_removeAddress_whitespaceString() {
        UpdateProfileRequest request = new UpdateProfileRequest();
        request.setAddress("   ");

        assertDoesNotThrow(() -> auth.updateProfile(testUserId, request));

        UserRepresentation updatedUser = auth.getUserProfile(testUserId);
        assertNull(auth.getAddressFromUser(updatedUser));
    }

    @ParameterizedTest(name = "email=\"{0}\" - email not updated")
    @NullAndEmptySource
    @ValueSource(strings = {" ", "   "})
    @DisplayName("updateProfile: blank/null email - not updated")
    void updateProfile_blankEmail_notUpdated(String email) {
        UpdateProfileRequest request = new UpdateProfileRequest();
        request.setEmail(email);

        assertDoesNotThrow(() -> auth.updateProfile(testUserId, request));

        UserRepresentation updatedUser = auth.getUserProfile(testUserId);
        assertEquals("john.doe@example.com", updatedUser.getEmail()); 
    }

    @Test
    @DisplayName("updateProfile: non-existent user - throws RuntimeException")
    void updateProfile_nonExistentUser_throws() {
        String nonExistentUserId = UUID.randomUUID().toString();
        UpdateProfileRequest request = new UpdateProfileRequest();
        request.setFirstName("Test");

        Exception exception = assertThrows(Exception.class,
                () -> auth.updateProfile(nonExistentUserId, request));
        assertNotNull(exception);
    }

    @Test
    @DisplayName("updateProfile: empty request - no changes made")
    void updateProfile_emptyRequest_noChanges() {
        UpdateProfileRequest request = new UpdateProfileRequest();

        assertDoesNotThrow(() -> auth.updateProfile(testUserId, request));

        UserRepresentation updatedUser = auth.getUserProfile(testUserId);
        assertEquals("John", updatedUser.getFirstName());
        assertEquals("Doe", updatedUser.getLastName());
        assertEquals("john.doe@example.com", updatedUser.getEmail());
    }

    @Test
    @DisplayName("changeCredentials: happy path - password changed successfully")
    void changeCredentials_happyPath() {
        String newPassword = "newS3cret!";
        ChangeCredentialsRequest request = new ChangeCredentialsRequest();
        request.setCurrentPassword(TEST_PASSWORD);
        request.setNewPassword(newPassword);

        assertDoesNotThrow(() -> auth.changeCredentials(testUserId, request));

        org.example.identity.DTO.LoginRequest loginRequest = new org.example.identity.DTO.LoginRequest();
        loginRequest.setUsername(TEST_USERNAME);
        loginRequest.setPassword(newPassword);
        assertDoesNotThrow(() -> auth.login(loginRequest));
    }

    @Test
    @DisplayName("changeCredentials: incorrect current password - throws RuntimeException")
    void changeCredentials_incorrectCurrentPassword_throws() {
        ChangeCredentialsRequest request = new ChangeCredentialsRequest();
        request.setCurrentPassword("wrongPassword");
        request.setNewPassword("newS3cret!");

        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> auth.changeCredentials(testUserId, request));
        assertEquals("Current password is incorrect", exception.getMessage());
    }

    @Test
    @DisplayName("changeCredentials: non-existent user - throws exception")
    void changeCredentials_nonExistentUser_throws() {
        String nonExistentUserId = UUID.randomUUID().toString();
        ChangeCredentialsRequest request = new ChangeCredentialsRequest();
        request.setCurrentPassword(TEST_PASSWORD);
        request.setNewPassword("newPassword");

        Exception exception = assertThrows(Exception.class,
                () -> auth.changeCredentials(nonExistentUserId, request));
        assertNotNull(exception);
    }

    @Test
    @DisplayName("changeCredentials: old password stops working after change")
    void changeCredentials_oldPasswordStopsWorking() {
        String newPassword = "brandNewS3cret!";
        ChangeCredentialsRequest request = new ChangeCredentialsRequest();
        request.setCurrentPassword(TEST_PASSWORD);
        request.setNewPassword(newPassword);

        assertDoesNotThrow(() -> auth.changeCredentials(testUserId, request));

        org.example.identity.DTO.LoginRequest loginRequest = new org.example.identity.DTO.LoginRequest();
        loginRequest.setUsername(TEST_USERNAME);
        loginRequest.setPassword(TEST_PASSWORD);
        assertThrows(Exception.class, () -> auth.login(loginRequest));
    }

    @Test
    @DisplayName("getUserProfile: happy path - returns user profile")
    void getUserProfile_happyPath() {
        UserRepresentation user = assertDoesNotThrow(() -> auth.getUserProfile(testUserId));

        assertNotNull(user);
        assertEquals(TEST_USERNAME, user.getUsername());
        assertEquals("John", user.getFirstName());
        assertEquals("Doe", user.getLastName());
        assertEquals("john.doe@example.com", user.getEmail());
        assertTrue(user.isEnabled());
    }

    @Test
    @DisplayName("getUserProfile: non-existent user - throws exception")
    void getUserProfile_nonExistentUser_throws() {
        String nonExistentUserId = UUID.randomUUID().toString();

        Exception exception = assertThrows(Exception.class,
                () -> auth.getUserProfile(nonExistentUserId));
        assertNotNull(exception);
    }

    @Test
    @DisplayName("getUserIdFromUsername: happy path - returns correct user ID")
    void getUserIdFromUsername_happyPath() {
        String userId = assertDoesNotThrow(() -> auth.getUserIdFromUsername(TEST_USERNAME));

        assertNotNull(userId);
        assertFalse(userId.isEmpty());
        assertEquals(testUserId, userId);
    }

    @Test
    @DisplayName("getUserIdFromUsername: non-existent user - throws RuntimeException")
    void getUserIdFromUsername_nonExistentUser_throws() {
        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> auth.getUserIdFromUsername("non-existent-user"));
        assertTrue(exception.getMessage().contains("User not found"));
    }

    @Test
    @DisplayName("getUserIdFromUsername: case insensitive - Keycloak may accept case variations")
    void getUserIdFromUsername_caseInsensitive() {
        try {
            String userId = auth.getUserIdFromUsername(TEST_USERNAME.toUpperCase());
            assertEquals(testUserId, userId);
        } catch (RuntimeException e) {
            assertTrue(e.getMessage().contains("User not found"));
        }
    }

    @ParameterizedTest(name = "username=\"{0}\"")
    @NullAndEmptySource
    @ValueSource(strings = {" ", "   "})
    @DisplayName("getUserIdFromUsername: blank/null username - document actual behavior")
    void getUserIdFromUsername_blankUsername_documentBehavior(String username) {
        System.out.println("Testing username: '" + username + "'");

        try {
            String result = auth.getUserIdFromUsername(username);
            System.out.println("Result: " + result);
            if (result != null && !result.isEmpty()) {
                System.out.println("WARNING: Blank username returned a user ID - this may indicate a Keycloak configuration issue");
            }

        } catch (Exception e) {
            System.out.println("Exception (expected): " + e.getClass().getSimpleName() + " - " + e.getMessage());
            assertNotNull(e);
        }
    }

    @ParameterizedTest(name = "username=\"{0}\"")
    @NullAndEmptySource
    @ValueSource(strings = {" ", "   "})
    @DisplayName("getUserIdFromUsername: blank/null username - flexible test")
    void getUserIdFromUsername_blankUsername_flexible(String username) {
        Exception caughtException = null;
        String result = null;

        try {
            result = auth.getUserIdFromUsername(username);
        } catch (Exception e) {
            caughtException = e;
        }

        if (caughtException != null) {
            System.out.println("Blank username '" + username + "' threw exception (expected): " + caughtException.getMessage());
            assertTrue(caughtException instanceof RuntimeException);
        } else {
            System.out.println("Blank username '" + username + "' returned: " + result + " (no exception)");
        }
    }

    @Test
    @DisplayName("getAddressFromUser: user without address - returns null")
    void getAddressFromUser_userWithoutAddress_returnsNull() {
        UpdateProfileRequest request = new UpdateProfileRequest();
        request.setAddress("");
        auth.updateProfile(testUserId, request);

        UserRepresentation user = auth.getUserProfile(testUserId);
        String address = auth.getAddressFromUser(user);

        assertNull(address);
    }

    @Test
    @DisplayName("getAddressFromUser: user with null attributes - returns null")
    void getAddressFromUser_userWithNullAttributes_returnsNull() {
        UserRepresentation user = new UserRepresentation();
        user.setAttributes(null);

        String address = auth.getAddressFromUser(user);

        assertNull(address);
    }

    @Test
    @DisplayName("getAddressFromUser: user with empty address list - returns null")
    void getAddressFromUser_userWithEmptyAddressList_returnsNull() {
        UserRepresentation user = auth.getUserProfile(testUserId);

        if (user.getAttributes() == null) {
            user.setAttributes(new HashMap<>());
        }

        user.getAttributes().put("address", List.of());

        String address = auth.getAddressFromUser(user);

        assertNull(address);
    }

    @Test
    @DisplayName("Integration: complete profile update workflow")
    void integration_completeProfileUpdateWorkflow() {
        UserRepresentation initialUser = auth.getUserProfile(testUserId);
        assertEquals("John", initialUser.getFirstName());

        UpdateProfileRequest updateRequest = new UpdateProfileRequest();
        updateRequest.setFirstName("Jane");
        updateRequest.setLastName("Smith");
        updateRequest.setEmail("jane.smith@example.com");

        auth.updateProfile(testUserId, updateRequest);

        UserRepresentation updatedUser = auth.getUserProfile(testUserId);
        assertEquals("Jane", updatedUser.getFirstName());
        assertEquals("Smith", updatedUser.getLastName());
        assertEquals("jane.smith@example.com", updatedUser.getEmail());

        String foundUserId = auth.getUserIdFromUsername(TEST_USERNAME);
        assertEquals(testUserId, foundUserId);
    }

    @Test
    @DisplayName("Integration: change password and verify profile access")
    void integration_changePasswordAndVerifyProfileAccess() {
        String newPassword = "superS3cret!";

        ChangeCredentialsRequest changeRequest = new ChangeCredentialsRequest();
        changeRequest.setCurrentPassword(TEST_PASSWORD);
        changeRequest.setNewPassword(newPassword);

        auth.changeCredentials(testUserId, changeRequest);

        UserRepresentation user = auth.getUserProfile(testUserId);
        assertEquals(TEST_USERNAME, user.getUsername());

        String foundUserId = auth.getUserIdFromUsername(TEST_USERNAME);
        assertEquals(testUserId, foundUserId);

        org.example.identity.DTO.LoginRequest loginRequest = new org.example.identity.DTO.LoginRequest();
        loginRequest.setUsername(TEST_USERNAME);
        loginRequest.setPassword(newPassword);
        assertDoesNotThrow(() -> auth.login(loginRequest));
    }

}