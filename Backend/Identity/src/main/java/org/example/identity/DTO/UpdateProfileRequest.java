package org.example.identity.DTO;

import jakarta.validation.constraints.Email;
import lombok.Data;

@Data
public class UpdateProfileRequest {
    private String firstName;
    private String lastName;
    @Email
    private String email;
    private String address;
}