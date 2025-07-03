package com.example.jwtproject.dto;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class AuthResponse extends TokenResponse {
    private UUID userId;
    private String username;
    private String email;
    private String role;

    public AuthResponse(String accessToken, String refreshToken, Long expiresIn, UUID userId, String username, String email, String role) {
        super(accessToken, refreshToken, expiresIn);
        this.userId = userId;
        this.username = username;
        this.email = email;
        this.role = role;
    }
}
