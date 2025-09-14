package org.example.identity.services;

import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import org.example.identity.DTO.RegisterRequest;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final Keycloak keycloak;
    private final String keycloakRealm;
    @Value("${keycloak.server-url}")
    private String keycloakServerUrl;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.client-secret}")
    private String clientSecret;

    public void register(RegisterRequest request) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(request.getUsername());
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setEmail(request.getEmail());
        user.setEnabled(true);

        Map<String, List<String>> attributes = new HashMap<>();
        if (request.getAddress() != null && !request.getAddress().isBlank()) {
            attributes.put("city", List.of(request.getAddress()));
        }
        user.setAttributes(attributes);

        Response response = keycloak.realm(keycloakRealm).users().create(user);
        if (response.getStatus() != 201) {
            throw new RuntimeException("Failed to create user: " + response.getStatus());
        }

        String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");

        CredentialRepresentation password = new CredentialRepresentation();
        password.setTemporary(false);
        password.setType(CredentialRepresentation.PASSWORD);
        password.setValue(request.getPassword());
        keycloak.realm(keycloakRealm).users().get(userId).resetPassword(password);

        String clientId = keycloak.realm(keycloakRealm)
                .clients()
                .findByClientId("identity-service")
                .get(0)
                .getId();

        RoleRepresentation role = keycloak.realm(keycloakRealm)
                .clients()
                .get(clientId)
                .roles()
                .get(request.getRole())
                .toRepresentation();

        if (role == null) {
            throw new IllegalStateException("Role not found: " + request.getRole());
        }

        keycloak.realm(keycloakRealm)
                .users()
                .get(userId)
                .roles()
                .clientLevel(clientId)
                .add(Collections.singletonList(role));
    }
}

