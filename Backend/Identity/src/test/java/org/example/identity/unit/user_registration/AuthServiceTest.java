package org.example.identity.unit.user_registration;

import org.example.identity.DTO.RegisterRequest;
import org.example.identity.services.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.*;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;

import jakarta.ws.rs.core.Response;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.net.URI;
import java.util.List;
import java.util.NoSuchElementException;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {
    private static final String REALM = "IdentityRealm";
    private static final String ORG_CLIENT_ID = "identity-service";
    private static final String INTERNAL_CLIENT_ID = "clientId";
    private static final String ROLE = "guest";
    private static final String USER_ID = "123";

    @Mock private Keycloak keycloak;
    @Mock private RealmResource realmResource;
    @Mock private UsersResource usersResource;
    @Mock private UserResource userResource;

    @Mock private ClientsResource clientsResource;
    @Mock private ClientResource clientResource;
    @Mock private RolesResource rolesResource;
    @Mock private RoleResource roleResource;
    @Mock private RoleMappingResource roleMappingResource;
    @Mock private RoleScopeResource roleScopeResource;

    private AuthService authService;

    @BeforeEach
    void setup() throws Exception {
        authService = new AuthService(keycloak, null, null);
        Field realmField = AuthService.class.getDeclaredField("keycloakRealm");
        realmField.setAccessible(true);
        realmField.set(authService, REALM);

        when(keycloak.realm(REALM)).thenReturn(realmResource);
        when(realmResource.users()).thenReturn(usersResource);
    }

    private RegisterRequest baseOkRequest() {
        RegisterRequest r = new RegisterRequest();
        r.setUsername("testUser");
        r.setPassword("secret");
        r.setFirstName("Test");
        r.setLastName("User");
        r.setEmail("test@example.com");
        r.setAddress("Novi Sad");
        r.setRole(ROLE);
        return r;
    }

    private Response createdResponse(String id) {
        return Response.created(URI.create("http://localhost/users/" + id)).build();
    }

    private void okCreateUserFlow() {
        when(usersResource.create(any(UserRepresentation.class))).thenReturn(createdResponse(AuthServiceTest.USER_ID));
        when(usersResource.get(AuthServiceTest.USER_ID)).thenReturn(userResource);
    }

    private void mockClientAndUserMappingBase() {
        when(realmResource.clients()).thenReturn(clientsResource);
        ClientRepresentation cr = new ClientRepresentation(); cr.setId(INTERNAL_CLIENT_ID);
        when(clientsResource.findByClientId(ORG_CLIENT_ID)).thenReturn(List.of(cr));
        when(clientsResource.get(INTERNAL_CLIENT_ID)).thenReturn(clientResource);
        when(clientResource.roles()).thenReturn(rolesResource);
        when(userResource.roles()).thenReturn(roleMappingResource);
        when(roleMappingResource.clientLevel(INTERNAL_CLIENT_ID)).thenReturn(roleScopeResource);
    }

    private void mockRoleFound() {
        RoleRepresentation roleRep = new RoleRepresentation();
        roleRep.setName(AuthServiceTest.ROLE);
        when(rolesResource.get(AuthServiceTest.ROLE)).thenReturn(roleResource);
        when(roleResource.toRepresentation()).thenReturn(roleRep);
    }

    private void mockClientAndRolesResourceOnly() {
        when(realmResource.clients()).thenReturn(clientsResource);
        ClientRepresentation cr = new ClientRepresentation(); cr.setId(INTERNAL_CLIENT_ID);
        when(clientsResource.findByClientId(ORG_CLIENT_ID)).thenReturn(List.of(cr));
        when(clientsResource.get(INTERNAL_CLIENT_ID)).thenReturn(clientResource);
        when(clientResource.roles()).thenReturn(rolesResource);
    }

    @Test
    @DisplayName("register: happy path – user, password, found client i assigned role")
    void register_happyPath() {
        RegisterRequest request = new RegisterRequest();
        request.setUsername("testUser");
        request.setPassword("secret");
        request.setFirstName("Test");
        request.setLastName("User");
        request.setEmail("test@example.com");
        request.setAddress("Novi Sad");
        request.setRole(ROLE);

        Response response = mock(Response.class);
        when(response.getStatus()).thenReturn(201);
        when(response.getLocation()).thenReturn(URI.create("http://localhost/users/123"));
        when(usersResource.create(any(UserRepresentation.class))).thenReturn(response);

        when(usersResource.get(USER_ID)).thenReturn(userResource);

        when(realmResource.clients()).thenReturn(clientsResource);
        ClientRepresentation clientRep = new ClientRepresentation();
        clientRep.setId(INTERNAL_CLIENT_ID);
        when(clientsResource.findByClientId(ORG_CLIENT_ID))
                .thenReturn(List.of(clientRep));
        when(clientsResource.get(INTERNAL_CLIENT_ID)).thenReturn(clientResource);
        when(clientResource.roles()).thenReturn(rolesResource);
        when(rolesResource.get(ROLE)).thenReturn(roleResource);

        RoleRepresentation roleRep = new RoleRepresentation();
        roleRep.setName(ROLE);
        when(roleResource.toRepresentation()).thenReturn(roleRep);

        when(userResource.roles()).thenReturn(roleMappingResource);
        when(roleMappingResource.clientLevel(INTERNAL_CLIENT_ID)).thenReturn(roleScopeResource);

        assertDoesNotThrow(() -> authService.register(request));

        verify(usersResource).create(any(UserRepresentation.class));
        verify(userResource).resetPassword(any());
        verify(roleScopeResource).add(List.of(roleRep));
    }

    @Test
    @DisplayName("register: creating is returning !=201 → throws RuntimeException")
    void register_whenCreateFails_stopsEarly() {
        var req = new RegisterRequest();
        req.setUsername("u"); req.setAddress("a");

        Response bad = mock(Response.class);
        when(bad.getStatus()).thenReturn(400);
        when(usersResource.create(any())).thenReturn(bad);

        RuntimeException ex = assertThrows(RuntimeException.class, () -> authService.register(req));
        assertTrue(ex.getMessage().contains("Failed to create user: 400"));

        verify(usersResource).create(any(UserRepresentation.class));
        verifyNoInteractions(clientsResource, clientResource, rolesResource, roleResource, roleMappingResource, roleScopeResource);
    }

    @Test
    @DisplayName("register: 201 without Location → NullPointerException")
    void register_when201ButNoLocation_throws() {
        var req = baseOkRequest();

        Response resp = mock(Response.class);
        when(resp.getStatus()).thenReturn(201);
        when(resp.getLocation()).thenReturn(null);
        when(usersResource.create(any())).thenReturn(resp);

        assertThrows(NullPointerException.class, () -> authService.register(req));
    }

    @Test
    @DisplayName("register: resetPassword throws → propagation")
    void register_whenResetPasswordFails_propagates() {
        RegisterRequest r = baseOkRequest();
        Response resp = createdResponse(USER_ID);
        when(usersResource.create(any())).thenReturn(resp);
        when(usersResource.get(USER_ID)).thenReturn(userResource);

        doThrow(new RuntimeException("boom")).when(userResource).resetPassword(any());

        assertThrows(RuntimeException.class, () -> authService.register(r));
    }

    @Test
    @DisplayName("register: clientId does not exist → NoSuchElementException")
    void register_whenClientNotFound_throws() {
        RegisterRequest r = baseOkRequest();
        okCreateUserFlow();

        when(realmResource.clients()).thenReturn(clientsResource);
        when(clientsResource.findByClientId(ORG_CLIENT_ID)).thenReturn(List.of());

        // Changed from IndexOutOfBoundsException to NoSuchElementException
        assertThrows(NoSuchElementException.class, () -> authService.register(r));
    }

    @Test
    @DisplayName("register: role null → IllegalStateException")
    void register_whenRoleMissing_throws() {
        RegisterRequest r = baseOkRequest();
        okCreateUserFlow();
        mockClientAndRolesResourceOnly();

        when(rolesResource.get(ROLE)).thenReturn(roleResource);
        when(roleResource.toRepresentation()).thenReturn(null);

        assertThrows(IllegalStateException.class, () -> authService.register(r));
    }

    @Test
    @DisplayName("register: role assignment throws → propagation")
    void register_whenRoleAssignmentFails_propagates() {
        RegisterRequest r = baseOkRequest();
        okCreateUserFlow();
        ClientRepresentation cr = new ClientRepresentation(); cr.setId(INTERNAL_CLIENT_ID);
        when(realmResource.clients()).thenReturn(clientsResource);
        when(clientsResource.findByClientId(ORG_CLIENT_ID)).thenReturn(List.of(cr));
        when(clientsResource.get(INTERNAL_CLIENT_ID)).thenReturn(clientResource);
        when(clientResource.roles()).thenReturn(rolesResource);

        RoleRepresentation roleRep = new RoleRepresentation(); roleRep.setName(ROLE);
        when(rolesResource.get(ROLE)).thenReturn(roleResource);
        when(roleResource.toRepresentation()).thenReturn(roleRep);
        when(usersResource.get(USER_ID)).thenReturn(userResource);
        when(userResource.roles()).thenReturn(roleMappingResource);
        when(roleMappingResource.clientLevel(INTERNAL_CLIENT_ID)).thenReturn(roleScopeResource);

        doThrow(new RuntimeException("assign fail")).when(roleScopeResource).add(anyList());

        assertThrows(RuntimeException.class, () -> authService.register(r));
    }

    @ParameterizedTest(name = "address=\"{0}\" → must not set address field")
    @NullAndEmptySource
    @ValueSource(strings = {" ", "   "})
    @DisplayName("register: blank/null address → without 'address' attribute")
    void register_whenAddressBlank_addressNotSet(String addr) {
        RegisterRequest r = baseOkRequest();
        r.setAddress(addr);

        when(usersResource.create(any())).thenReturn(createdResponse("id-1"));
        when(usersResource.get("id-1")).thenReturn(userResource);

        when(realmResource.clients()).thenReturn(clientsResource);
        when(clientsResource.findByClientId(ORG_CLIENT_ID)).thenReturn(List.of());

        assertThrows(RuntimeException.class, () -> authService.register(r));

        ArgumentCaptor<UserRepresentation> cap = ArgumentCaptor.forClass(UserRepresentation.class);
        verify(usersResource).create(cap.capture());
        assertTrue(cap.getValue().getAttributes().isEmpty());
    }

    @Test
    @DisplayName("Successful registration captures correct UserRepresentation (incl. password)")
    void success_capturesCorrectUserRepresentation() {
        okCreateUserFlow();
        mockClientAndUserMappingBase();
        mockRoleFound();

        RegisterRequest r = baseOkRequest();

        assertDoesNotThrow(() -> authService.register(r));

        ArgumentCaptor<UserRepresentation> cap = ArgumentCaptor.forClass(UserRepresentation.class);
        verify(usersResource).create(cap.capture());
        UserRepresentation u = cap.getValue();
        assertEquals("testUser", u.getUsername());
        assertEquals("Test", u.getFirstName());
        assertEquals("User", u.getLastName());
        assertEquals("test@example.com", u.getEmail());
        assertTrue(u.isEnabled());
        // Changed from "city" to "address"
        assertEquals(List.of("Novi Sad"), u.getAttributes().get("address"));

        ArgumentCaptor<CredentialRepresentation> pw = ArgumentCaptor.forClass(CredentialRepresentation.class);
        verify(userResource).resetPassword(pw.capture());
        assertEquals(CredentialRepresentation.PASSWORD, pw.getValue().getType());
        assertFalse(pw.getValue().isTemporary());
        assertEquals("secret", pw.getValue().getValue());

        verify(roleScopeResource).add(argThat(list -> list.size()==1 && "guest".equals(list.getFirst().getName())));
        verifyNoMoreInteractions(roleScopeResource);
    }

    @Test
    @DisplayName("Strict call order: create → resetPassword → roles.clientLevel.add")
    void callsAreInStrictOrder() {
        okCreateUserFlow();
        mockClientAndUserMappingBase();
        mockRoleFound();

        RegisterRequest r = baseOkRequest();

        InOrder inOrder = inOrder(usersResource, userResource, rolesResource, roleMappingResource, roleScopeResource);

        authService.register(r);

        inOrder.verify(usersResource).create(any());
        inOrder.verify(userResource).resetPassword(any());
        inOrder.verify(userResource).roles();
        inOrder.verify(roleMappingResource).clientLevel(INTERNAL_CLIENT_ID);
        inOrder.verify(roleScopeResource).add(anyList());
    }
}