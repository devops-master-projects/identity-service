package org.example.identity.unit.user_profile;

import org.example.identity.DTO.ChangeCredentialsRequest;
import org.example.identity.DTO.LoginRequest;
import org.example.identity.DTO.UpdateProfileRequest;
import org.example.identity.services.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthService Tests")
class AuthServiceTest {

    @Mock
    private Keycloak keycloak;

    @Mock
    private RealmResource realmResource;

    @Mock
    private UsersResource usersResource;

    @Mock
    private UserResource userResource;

    @InjectMocks
    private AuthService authService;

    private final String TEST_REALM = "test-realm";
    private final String TEST_USER_ID = "test-user-id";
    private final String TEST_USERNAME = "testuser";

    @BeforeEach
    void setUp() throws Exception {
        setPrivateField("keycloakRealm", TEST_REALM);
        setPrivateField("keycloakServerUrl", "http://localhost:8080");
        setPrivateField("clientId", "test-client");
        setPrivateField("clientSecret", "test-secret");

        when(keycloak.realm(TEST_REALM)).thenReturn(realmResource);
        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.get(TEST_USER_ID)).thenReturn(userResource);
    }

    private void setPrivateField(String fieldName, String value) throws Exception {
        java.lang.reflect.Field field = AuthService.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(authService, value);
    }

    @Test
    @DisplayName("Should update all fields when all fields are provided")
    void updateProfile_ShouldUpdateAllFields_WhenAllFieldsProvided() {
        UpdateProfileRequest request = new UpdateProfileRequest();
        request.setFirstName("NewFirstName");
        request.setLastName("NewLastName");
        request.setEmail("newemail@example.com");
        request.setAddress("New Address");

        UserRepresentation existingUser = createTestUser();
        when(userResource.toRepresentation()).thenReturn(existingUser);

        authService.updateProfile(TEST_USER_ID, request);

        verify(userResource).update(argThat(user -> {
            assertEquals("NewFirstName", user.getFirstName());
            assertEquals("NewLastName", user.getLastName());
            assertEquals("newemail@example.com", user.getEmail());
            assertEquals("New Address", user.getAttributes().get("address").getFirst());
            return true;
        }));
    }

    @Test
    @DisplayName("Should update only provided fields when partial update is requested")
    void updateProfile_ShouldUpdateOnlyProvidedFields_WhenPartialUpdateRequested() {
        UpdateProfileRequest request = new UpdateProfileRequest();
        request.setFirstName("NewFirstName");

        UserRepresentation existingUser = createTestUser();
        when(userResource.toRepresentation()).thenReturn(existingUser);

        authService.updateProfile(TEST_USER_ID, request);

        verify(userResource).update(argThat(user -> {
            assertEquals("NewFirstName", user.getFirstName());
            assertEquals("OriginalLastName", user.getLastName());
            assertEquals("original@example.com", user.getEmail());
            return true;
        }));
    }

    @Test
    @DisplayName("Should remove address when blank address is provided")
    void updateProfile_ShouldRemoveAddress_WhenBlankAddressProvided() {
        UpdateProfileRequest request = new UpdateProfileRequest();
        request.setAddress("");

        UserRepresentation existingUser = createTestUser();
        Map<String, List<String>> attributes = new HashMap<>();
        attributes.put("address", List.of("Original Address"));
        existingUser.setAttributes(attributes);
        when(userResource.toRepresentation()).thenReturn(existingUser);

        authService.updateProfile(TEST_USER_ID, request);

        verify(userResource).update(argThat(user -> {
            assertNull(user.getAttributes().get("address"));
            return true;
        }));
    }

    @Test
    @DisplayName("Should ignore blank email when blank email is provided")
    void updateProfile_ShouldIgnoreBlankEmail_WhenBlankEmailProvided() {
        UpdateProfileRequest request = new UpdateProfileRequest();
        request.setEmail("");

        UserRepresentation existingUser = createTestUser();
        when(userResource.toRepresentation()).thenReturn(existingUser);

        authService.updateProfile(TEST_USER_ID, request);

        verify(userResource).update(argThat(user -> {
            assertEquals("original@example.com", user.getEmail());
            return true;
        }));
    }

    @Test
    @DisplayName("Should create attributes map when user has no existing attributes")
    void updateProfile_ShouldCreateAttributesMap_WhenUserHasNoAttributes() {
        UpdateProfileRequest request = new UpdateProfileRequest();
        request.setAddress("New Address");

        UserRepresentation existingUser = createTestUser();
        existingUser.setAttributes(null);
        when(userResource.toRepresentation()).thenReturn(existingUser);

        authService.updateProfile(TEST_USER_ID, request);

        verify(userResource).update(argThat(user -> {
            assertNotNull(user.getAttributes());
            assertEquals("New Address", user.getAttributes().get("address").getFirst());
            return true;
        }));
    }

    @Test
    @DisplayName("Should throw exception when user is not found")
    void updateProfile_ShouldThrowException_WhenUserNotFound() {
        UpdateProfileRequest request = new UpdateProfileRequest();
        when(userResource.toRepresentation()).thenReturn(null);

        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> authService.updateProfile(TEST_USER_ID, request));
        assertEquals("User not found: " + TEST_USER_ID, exception.getMessage());
        verify(userResource, never()).update(any());
    }

    @Test
    @DisplayName("Should change password when current password is correct")
    void changeCredentials_ShouldChangePassword_WhenCurrentPasswordIsCorrect() {
        ChangeCredentialsRequest request = new ChangeCredentialsRequest();
        request.setCurrentPassword("currentPassword");
        request.setNewPassword("newPassword");

        UserRepresentation existingUser = createTestUser();
        when(userResource.toRepresentation()).thenReturn(existingUser);

        AuthService spyAuthService = spy(authService);

        doAnswer(invocation -> {
            LoginRequest loginRequest = invocation.getArgument(0);
            if ("currentPassword".equals(loginRequest.getPassword())) {
                return Map.of("access_token", "dummy_token");
            } else {
                throw new RuntimeException("Login failed");
            }
        }).when(spyAuthService).login(any(LoginRequest.class));

        spyAuthService.changeCredentials(TEST_USER_ID, request);

        verify(spyAuthService).login(argThat(loginRequest -> {
            assertEquals(TEST_USERNAME, loginRequest.getUsername());
            assertEquals("currentPassword", loginRequest.getPassword());
            return true;
        }));

        verify(userResource).resetPassword(argThat(credential -> {
            assertEquals(CredentialRepresentation.PASSWORD, credential.getType());
            assertEquals("newPassword", credential.getValue());
            assertFalse(credential.isTemporary());
            return true;
        }));
    }

    @Test
    @DisplayName("Should throw exception when current password is incorrect")
    void changeCredentials_ShouldThrowException_WhenCurrentPasswordIsIncorrect() {
        ChangeCredentialsRequest request = new ChangeCredentialsRequest();
        request.setCurrentPassword("wrongPassword");
        request.setNewPassword("newPassword");

        UserRepresentation existingUser = createTestUser();
        when(userResource.toRepresentation()).thenReturn(existingUser);

        AuthService spyAuthService = spy(authService);

        doAnswer(invocation -> {
            LoginRequest loginRequest = invocation.getArgument(0);
            if ("currentPassword".equals(loginRequest.getPassword())) {
                return Map.of("access_token", "dummy_token");
            } else {
                throw new RuntimeException("Login failed");
            }
        }).when(spyAuthService).login(any(LoginRequest.class));

        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> spyAuthService.changeCredentials(TEST_USER_ID, request));
        assertEquals("Current password is incorrect", exception.getMessage());
        verify(userResource, never()).resetPassword(any());
    }

    @Test
    @DisplayName("Should throw exception when user is not found during password change")
    void changeCredentials_ShouldThrowException_WhenUserNotFound() {
        ChangeCredentialsRequest request = new ChangeCredentialsRequest();
        request.setCurrentPassword("currentPassword");
        request.setNewPassword("newPassword");

        when(userResource.toRepresentation()).thenReturn(null);

        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> authService.changeCredentials(TEST_USER_ID, request));
        assertEquals("User not found: " + TEST_USER_ID, exception.getMessage());
        verify(userResource, never()).resetPassword(any());
    }

    @Test
    @DisplayName("Should verify current password first before changing")
    void changeCredentials_ShouldVerifyCurrentPasswordFirst_BeforeChanging() {
        ChangeCredentialsRequest request = new ChangeCredentialsRequest();
        request.setCurrentPassword("currentPassword");
        request.setNewPassword("newPassword");

        UserRepresentation existingUser = createTestUser();
        when(userResource.toRepresentation()).thenReturn(existingUser);

        AuthService spyAuthService = spy(authService);

        doAnswer(invocation -> {
            LoginRequest loginRequest = invocation.getArgument(0);
            if ("currentPassword".equals(loginRequest.getPassword())) {
                return Map.of("access_token", "dummy_token");
            } else {
                throw new RuntimeException("Login failed");
            }
        }).when(spyAuthService).login(any(LoginRequest.class));

        spyAuthService.changeCredentials(TEST_USER_ID, request);

        InOrder inOrder = inOrder(spyAuthService, userResource);
        inOrder.verify(spyAuthService).login(any(LoginRequest.class));
        inOrder.verify(userResource).resetPassword(any(CredentialRepresentation.class));
    }

    private UserRepresentation createTestUser() {
        UserRepresentation user = new UserRepresentation();
        user.setId(TEST_USER_ID);
        user.setUsername(TEST_USERNAME);
        user.setFirstName("OriginalFirstName");
        user.setLastName("OriginalLastName");
        user.setEmail("original@example.com");
        user.setEnabled(true);
        return user;
    }
}