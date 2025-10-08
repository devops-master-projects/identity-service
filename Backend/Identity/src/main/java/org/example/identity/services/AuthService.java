package org.example.identity.services;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import org.example.identity.DTO.ChangeCredentialsRequest;
import org.example.identity.DTO.LoginRequest;
import org.example.identity.DTO.RegisterRequest;
import org.example.identity.DTO.UpdateProfileRequest;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final Keycloak keycloak;
    private final String keycloakRealm;
    private final RestTemplate restTemplate;

    @Value("${keycloak.server-url}")
    private String keycloakServerUrl;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.client-secret}")
    private String clientSecret;

    @Value("${notification.service.url}")
    private String notificationServiceUrl;

    @Value("${booking.service.url}")
    private String bookingServiceUrl;

    @Value("${accommodation.service.url}")
    private String accommodationServiceUrl;

    // Constants for attribute names - choose one consistently
    private static final String ADDRESS_ATTRIBUTE = "address"; // Changed from "city" to "address"

    public void register(RegisterRequest request) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(request.getUsername());
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setEmail(request.getEmail());
        user.setEnabled(true);

        Map<String, List<String>> attributes = new HashMap<>();
        if (request.getAddress() != null && !request.getAddress().isBlank()) {
            attributes.put(ADDRESS_ATTRIBUTE, List.of(request.getAddress()));
        }
        user.setAttributes(attributes);

        Response response = keycloak.realm(keycloakRealm).users().create(user);
        if (response.getStatus() != 201) {
            throw new RuntimeException("Failed to create user: " + response.getStatus());
        }
        System.out.println(request.getRole());
        String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
        System.out.println("userid: " + userId);

        CredentialRepresentation password = new CredentialRepresentation();
        password.setTemporary(false);
        password.setType(CredentialRepresentation.PASSWORD);
        password.setValue(request.getPassword());
        keycloak.realm(keycloakRealm).users().get(userId).resetPassword(password);

        String clientId = keycloak.realm(keycloakRealm)
                .clients()
                .findByClientId("identity-service")
                .getFirst()
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

        initializeNotificationSettings(userId, request.getRole());
    }

    private void initializeNotificationSettings(String userId, String role) {

        String url = String.format("%s/api/notification-settings/init?userId=%s&role=%s",
                notificationServiceUrl, userId, role);

        try {
            restTemplate.postForEntity(url, null, Void.class);
            System.out.printf("Initialized notification settings for userId=%s with role=%s%n",
                    userId, role);
        } catch (Exception e) {
            System.err.printf("Failed to initialize notification settings for userId=%s: %s%n",
                    userId, e.getMessage());
        }
    }

    public Map<String, Object> login(LoginRequest request) {
        String tokenUrl = keycloakServerUrl + "/realms/" + keycloakRealm + "/protocol/openid-connect/token";

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "password");
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("username", request.getUsername());
        body.add("password", request.getPassword());

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                tokenUrl,
                HttpMethod.POST,
                entity,
                Map.class
        );

        return response.getBody();
    }

    public void updateProfile(String userId, UpdateProfileRequest request) {
        UserResource userResource = keycloak.realm(keycloakRealm).users().get(userId);
        UserRepresentation user = userResource.toRepresentation();

        if (user == null) {
            throw new RuntimeException("User not found: " + userId);
        }

        if (request.getFirstName() != null) {
            user.setFirstName(request.getFirstName());
        }
        if (request.getLastName() != null) {
            user.setLastName(request.getLastName());
        }
        if (request.getEmail() != null && !request.getEmail().isBlank()) {
            user.setEmail(request.getEmail());
        }

        // Update custom attributes (address)
        Map<String, List<String>> attributes = user.getAttributes();
        if (attributes == null) {
            attributes = new HashMap<>();
        }

        if (request.getAddress() != null) {
            if (request.getAddress().isBlank()) {
                // Remove address if empty string is provided
                attributes.remove(ADDRESS_ATTRIBUTE);
            } else {
                // Update address with new value
                attributes.put(ADDRESS_ATTRIBUTE, List.of(request.getAddress()));
            }
        }
        user.setAttributes(attributes);

        userResource.update(user);
    }

    public void changeCredentials(String userId, ChangeCredentialsRequest request) {
        UserResource userResource = keycloak.realm(keycloakRealm).users().get(userId);
        UserRepresentation user = userResource.toRepresentation();

        if (user == null) {
            throw new RuntimeException("User not found: " + userId);
        }

        // Verify current password by attempting to login
        try {
            LoginRequest loginRequest = new LoginRequest();
            loginRequest.setUsername(user.getUsername());
            loginRequest.setPassword(request.getCurrentPassword());
            login(loginRequest);
        } catch (Exception e) {
            throw new RuntimeException("Current password is incorrect");
        }

        // Update password
        CredentialRepresentation newPassword = new CredentialRepresentation();
        newPassword.setTemporary(false);
        newPassword.setType(CredentialRepresentation.PASSWORD);
        newPassword.setValue(request.getNewPassword());
        userResource.resetPassword(newPassword);
    }

    public UserRepresentation getUserProfile(String userId) {
        UserResource userResource = keycloak.realm(keycloakRealm).users().get(userId);
        UserRepresentation user = userResource.toRepresentation();

        if (user == null) {
            throw new RuntimeException("User not found: " + userId);
        }

        return user;
    }

    public String getUserIdFromUsername(String username) {
        List<UserRepresentation> users = keycloak.realm(keycloakRealm)
                .users()
                .search(username, true);

        if (users.isEmpty()) {
            throw new RuntimeException("User not found: " + username);
        }

        return users.getFirst().getId();
    }

    public String getAddressFromUser(UserRepresentation user) {
        if (user.getAttributes() != null && user.getAttributes().containsKey(ADDRESS_ATTRIBUTE)) {
            List<String> addresses = user.getAttributes().get(ADDRESS_ATTRIBUTE);
            return addresses.isEmpty() ? null : addresses.getFirst();
        }
        return null;
    }


    @Transactional
    public void deleteAccount(Authentication authentication) {
        if (!(authentication.getPrincipal() instanceof Jwt jwt)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid authentication token");
        }

        String userId = jwt.getClaimAsString("sub");
        String role = extractRole(jwt).toLowerCase();
        System.out.printf("Deleting account for userId=%s role=%s%n", userId, role);

        validateDeletionEligibility(role, jwt);
        if ("host".equals(role)) {
            deleteAllHostAccommodations(jwt);
        }

        deleteUserFromKeycloak(userId);
    }

    private void validateDeletionEligibility(String role, Jwt jwt) {
        String url = switch (role) {
            case "guest" -> bookingServiceUrl + "/api/booking/guest/can-delete-account";
            case "host"  -> bookingServiceUrl + "/api/booking/host/can-delete-account";
            default -> throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported role: " + role);
        };

        Boolean canDelete = callRestService(url, HttpMethod.GET, jwt, Boolean.class);

        if (!Boolean.TRUE.equals(canDelete)) {
            String message = switch (role) {
                case "guest" -> "Guest cannot delete the account because there are active reservations.";
                case "host"  -> "Host cannot delete the account because there are future active reservations for managed accommodations.";
                default      -> "Account cannot be deleted due to active reservations.";
            };
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
        }
    }

    private void deleteAllHostAccommodations(Jwt jwt) {
        String url = accommodationServiceUrl + "/api/accommodations/host/all";
        callRestService(url, HttpMethod.DELETE, jwt, Void.class);
    }


    private void deleteUserFromKeycloak(String userId) {
        try {
            var users = keycloak.realm(keycloakRealm).users().get(userId);
            var userRepresentation = users.toRepresentation();
            if (userRepresentation == null) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found in Keycloak");
            }
            users.remove();
        } catch (NotFoundException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found in Keycloak");
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Failed to delete user from Keycloak: " + e.getMessage());
        }
    }

    private <T> T callRestService(String url, HttpMethod method, Jwt jwt, Class<T> responseType) {
        try {
            ResponseEntity<T> response = restTemplate.exchange(
                    url,
                    method,
                    new HttpEntity<>(null, buildAuthHeaders(jwt.getTokenValue())),
                    responseType
            );

            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new ResponseStatusException(
                        HttpStatus.BAD_GATEWAY,
                        "Failed calling service: " + url + " — status " + response.getStatusCode()
                );
            }

            return response.getBody();

        } catch (HttpClientErrorException | HttpServerErrorException e) {
            throw new ResponseStatusException(e.getStatusCode(),
                    "Service error: " + e.getResponseBodyAsString());
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Error contacting service: " + e.getMessage());
        }
    }



    private String extractRole(Jwt jwt) {
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess != null) {
            for (Object res : resourceAccess.values()) {
                if (res instanceof Map<?, ?> resMap && resMap.containsKey("roles")) {
                    @SuppressWarnings("unchecked")
                    List<String> roles = (List<String>) resMap.get("roles");
                    for (String role : roles) {
                        if (isBusinessRole(role)) {
                            return role.toLowerCase();
                        }
                    }
                }
            }
        }

        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
        if (realmAccess != null && realmAccess.containsKey("roles")) {
            @SuppressWarnings("unchecked")
            List<String> roles = (List<String>) realmAccess.get("roles");
            for (String role : roles) {
                if (isBusinessRole(role)) {
                    return role.toLowerCase();
                }
            }
        }

        return "unknown";
    }

    private boolean isBusinessRole(String role) {
        if (role == null) return false;
        String lower = role.toLowerCase();
        return switch (lower) {
            case "guest", "host", "admin" -> true;
            default -> false;
        };
    }


    private HttpHeaders buildAuthHeaders(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(token);
        return headers;
    }


}