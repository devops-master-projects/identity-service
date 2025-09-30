package org.example.identity.integration.user_registration;

import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.example.identity.DTO.RegisterRequest;
import org.example.identity.controllers.AuthController;
import org.example.identity.services.AuthService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
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
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@Testcontainers
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = {
                AuthControllerNoClientIT.BootConfig.class,
                AuthControllerNoClientIT.TestConfig.class,
                AuthControllerIT.GlobalHandler.class
        },
        properties = { "spring.main.allow-bean-definition-overriding=true" }
)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerNoClientIT {

    private static final String REALM = "IdentityRealm";

    @Container
    static KeycloakContainer kc =
            new KeycloakContainer("quay.io/keycloak/keycloak:26.0.0")
                    .withRealmImportFile("keycloak/identity-realm-noclient.json");

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration(exclude = {
            DataSourceAutoConfiguration.class,
            HibernateJpaAutoConfiguration.class,
            KafkaAutoConfiguration.class
    })
    @ComponentScan(basePackageClasses = AuthController.class)
    static class BootConfig { }

    @TestConfiguration
    static class TestConfig {
        @Bean @Primary
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
            return new AuthService(admin, REALM /* , "identity-service" */, null);
        }
    }

    private final MockMvc mockMvc;
    private final ObjectMapper objectMapper;

    @Autowired
    AuthControllerNoClientIT(MockMvc mockMvc, ObjectMapper objectMapper) {
        this.mockMvc = mockMvc;
        this.objectMapper = objectMapper;
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
    @DisplayName("POST /api/auth/register (realm without clients) → 5xx")
    void register_clientMissing_returns500() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(ok())))
                .andExpect(status().is5xxServerError());
    }
}
