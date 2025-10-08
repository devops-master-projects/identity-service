package org.example.identity.integration.user_registration;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.example.identity.DTO.RegisterRequest;
import org.example.identity.services.AuthService;
import org.junit.jupiter.api.*;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.web.client.RestTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.junit.jupiter.api.Assertions.*;

@Testcontainers
class AuthServiceNoClientIT {

    private static final String REALM = "IdentityRealm";

    @Container
    static KeycloakContainer kc =
            new KeycloakContainer("quay.io/keycloak/keycloak:26.0.0")
                    .withRealmImportFile("keycloak/identity-realm-noclient.json");

    Keycloak admin;
    AuthService auth;

    RestTemplate template;

    @BeforeEach
    void setUp() {
        admin = KeycloakBuilder.builder()
                .serverUrl(kc.getAuthServerUrl())
                .realm("master")
                .clientId("admin-cli")
                .username(kc.getAdminUsername())
                .password(kc.getAdminPassword())
                .build();

        auth = new AuthService(admin, REALM, template);

    }

    private RegisterRequest ok() {
        var r = new RegisterRequest();
        r.setUsername("it-user-noclient");
        r.setPassword("s3cret!");
        r.setFirstName("IT");
        r.setLastName("User");
        r.setEmail("it-user@example.com");
        r.setAddress("Novi Sad");
        r.setRole("guest");
        return r;
    }

    @Test
    @DisplayName("register: realm without clients → service throws error")
    void register_clientMissing_throws() {
        var ex = assertThrows(RuntimeException.class, () -> auth.register(ok()));
    }

    @Test
    @DisplayName("register: role = null → service throws error")
    void register_roleNull_throws() {
        var r = ok();
        r.setRole(null);
        assertThrows(RuntimeException.class, () -> auth.register(r));
    }

    @Test
    @DisplayName("register: role = blank → service throws error")
    void register_roleBlank_throws() {
        var r = ok();
        r.setRole("   ");
        assertThrows(RuntimeException.class, () -> auth.register(r));
    }
}
