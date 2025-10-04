package org.example.identity.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class HostProfileDto {
    private String id;
    private String firstName;
    private String lastName;
    private String email;
}
