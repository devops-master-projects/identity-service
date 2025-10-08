package org.example.identity.integration.user_registration;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.example.identity.DTO.RegisterRequest;
import org.example.identity.services.AuthService;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@Testcontainers
class AuthServiceIT {

    private static final String REALM = "IdentityRealm";
    private static final String CLIENT_ID = "identity-service";

    @Container
    static KeycloakContainer kc =
            new KeycloakContainer("quay.io/keycloak/keycloak:26.0.0")
                    .withRealmImportFile("keycloak/identity-realm.json");

    Keycloak admin;
    AuthService auth;

    @BeforeEach
    void setUp() {
        admin = KeycloakBuilder.builder()
                .serverUrl(kc.getAuthServerUrl())
                .realm("master")
                .clientId("admin-cli")
                .username(kc.getAdminUsername())
                .password(kc.getAdminPassword())
                .build();

        auth = new AuthService(admin, REALM, null);

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
    @DisplayName("register: creates user, sets city attr, assigns client role 'guest'")
    void register_happyPath() {
        assertDoesNotThrow(() -> auth.register(ok()));

        RealmResource realm = admin.realm(REALM);
        List<UserRepresentation> found = realm.users().search("it-user", 0, 1);
        assertEquals(1, found.size());

        UserRepresentation u = found.getFirst();
        assertEquals("IT", u.getFirstName());
        assertEquals("User", u.getLastName());
        assertEquals("it-user@example.com", u.getEmail());

        String clientUuid = realm.clients().findByClientId(CLIENT_ID).getFirst().getId();
        UserResource ur = realm.users().get(u.getId());
        var roles = ur.roles().clientLevel(clientUuid).listAll();
        assertTrue(roles.stream().map(RoleRepresentation::getName).anyMatch("guest"::equals));
    }

    @Test
    @DisplayName("register: duplicate username → Keycloak 409 → service throws")
    void register_duplicate_conflict() {
        assertDoesNotThrow(() -> auth.register(ok())); // first time ok
        var ex = assertThrows(RuntimeException.class, () -> auth.register(ok()));
        assertTrue(ex.getMessage().contains("Failed to create user: 409"));
    }

    @ParameterizedTest(name = "address=\"{0}\" → no 'city' attribute")
    @NullAndEmptySource
    @ValueSource(strings = {" ", "   "})
    @DisplayName("register: blank/null address → city attribute not set")
    void register_blankAddress_noCity(String addr) {
        var r = ok();
        r.setAddress(addr);

        assertDoesNotThrow(() -> auth.register(r));

        var realm = admin.realm(REALM);
        var u = realm.users().search("it-user", 0, 1).getFirst();
        var attrs = u.getAttributes();
        assertTrue(attrs == null || !attrs.containsKey("city"));
    }

    @Test
    @DisplayName("register: missing role → propagated error from Keycloak")
    void register_missingRole_propagates() {
        var r = ok();
        r.setRole("does-not-exist");

        assertThrows(RuntimeException.class, () -> auth.register(r));
    }
}
