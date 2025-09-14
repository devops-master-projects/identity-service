package org.example.identity.DTO;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class RegisterRequest {
    @NotBlank
    private String username;
    @NotBlank
    private String password;
    private String firstName;
    private String lastName;
    @NotBlank
    private String email;
    private String address;
    @NotBlank
    private String role;
}
