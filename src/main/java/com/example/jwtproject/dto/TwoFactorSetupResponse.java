package com.example.jwtproject.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TwoFactorSetupResponse {
    private String secret; // Base32 encoded secret for QR code generation
    private String qrCodeUri; // Data URI for the QR code image (e.g., otpauth://totp/...)
    private boolean enabled;
}
