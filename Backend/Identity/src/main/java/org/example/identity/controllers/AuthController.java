package org.example.identity.controllers;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.identity.DTO.ChangeCredentialsRequest;
import org.example.identity.DTO.LoginRequest;
import org.example.identity.DTO.RegisterRequest;
import org.example.identity.DTO.UpdateProfileRequest;
import org.example.identity.services.AuthService;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<String> register(@Valid @RequestBody RegisterRequest request) {
        authService.register(request);
        return ResponseEntity.ok("User registered successfully!");
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @GetMapping("/profile")
    public ResponseEntity<Map<String, Object>> getProfile(Authentication authentication) {
        String userId = getUserIdFromToken(authentication);
        UserRepresentation user = authService.getUserProfile(userId);

        Map<String, Object> profile = new HashMap<>();
        profile.put("id", user.getId());
        profile.put("username", user.getUsername());
        profile.put("firstName", user.getFirstName());
        profile.put("lastName", user.getLastName());
        profile.put("email", user.getEmail());

        if (user.getAttributes() != null && user.getAttributes().containsKey("address")) {
            List<String> addressList = user.getAttributes().get("address");
            if (!addressList.isEmpty()) {
                profile.put("address", addressList.getFirst());
            }
        }

        return ResponseEntity.ok(profile);
    }

    @PutMapping("/profile")
    public ResponseEntity<String> updateProfile(@Valid @RequestBody UpdateProfileRequest request,
                                                Authentication authentication) {
        String userId = getUserIdFromToken(authentication);
        authService.updateProfile(userId, request);
        return ResponseEntity.ok("Profile updated successfully!");
    }

    @PutMapping("/credentials")
    public ResponseEntity<String> changeCredentials(@Valid @RequestBody ChangeCredentialsRequest request,
                                                    Authentication authentication) {
        String userId = getUserIdFromToken(authentication);
        authService.changeCredentials(userId, request);
        return ResponseEntity.ok("Credentials updated successfully!");
    }

    private String getUserIdFromToken(Authentication authentication) {
        if (authentication.getPrincipal() instanceof Jwt jwt) {
            return jwt.getClaimAsString("sub");
        }
        throw new RuntimeException("Invalid authentication token");
    }
}