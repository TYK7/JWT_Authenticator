package com.example.jwtproject.exception;

public class TwoFactorAuthenticationRequiredException extends RuntimeException {
    private String userId;

    public TwoFactorAuthenticationRequiredException(String message, String userId) {
        super(message);
        this.userId = userId;
    }

    public String getUserId() {
        return userId;
    }
}