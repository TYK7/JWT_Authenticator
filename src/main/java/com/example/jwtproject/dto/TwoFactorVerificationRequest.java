package com.example.jwtproject.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class TwoFactorVerificationRequest {

    @NotBlank(message = "User ID cannot be blank") // Or username/email, depending on how you identify the user pre-2FA
    private String userId; // Assuming UUID as String

    @NotBlank(message = "2FA code cannot be blank")
    @Size(min = 6, max = 6, message = "2FA code must be 6 digits")
    private String code;
}
