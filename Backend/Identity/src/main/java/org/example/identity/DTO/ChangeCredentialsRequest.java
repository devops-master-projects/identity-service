package org.example.identity.DTO;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ChangeCredentialsRequest {
    @NotBlank
    private String currentPassword;
    @NotBlank
    private String newPassword;
}