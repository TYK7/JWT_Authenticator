package com.example.jwtproject.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class AuditLogService {

    private static final Logger auditLogger = LoggerFactory.getLogger("AUDIT_LOG"); // Separate logger for audit

    public void logEvent(String eventType, String username, String details) {
        // In a real application, this might write to a database table or a dedicated log file/stream.
        // For this example, we'll use a specific SLF4J logger.
        auditLogger.info("[{}] User: '{}', Event: '{}', Details: '{}'",
                LocalDateTime.now(), username, eventType, details);
    }

    public void logLoginSuccess(String username) {
        logEvent("LOGIN_SUCCESS", username, "User successfully logged in.");
    }

    public void logLoginFailure(String usernameOrEmail, String reason) {
        logEvent("LOGIN_FAILURE", usernameOrEmail, "Login attempt failed. Reason: " + reason);
    }

    public void logLogoutSuccess(String username) {
        logEvent("LOGOUT_SUCCESS", username, "User successfully logged out.");
    }

    public void logTokenIssued(String username, String tokenType) {
        logEvent("TOKEN_ISSUED", username, tokenType + " issued.");
    }

    public void logTokenRefreshSuccess(String username) {
        logEvent("TOKEN_REFRESH_SUCCESS", username, "Token refreshed successfully.");
    }

    public void logTokenRefreshFailure(String username, String reason) {
        logEvent("TOKEN_REFRESH_FAILURE", username, "Token refresh failed. Reason: " + reason);
    }

    public void logProtectedAccess(String username, String resource) {
        logEvent("PROTECTED_RESOURCE_ACCESS", username, "Accessed resource: " + resource);
    }

    public void logRegistrationSuccess(String username) {
        logEvent("USER_REGISTRATION_SUCCESS", username, "New user registered.");
    }

    public void logRegistrationFailure(String username, String reason) {
        logEvent("USER_REGISTRATION_FAILURE", username, "User registration failed. Reason: " + reason);
    }

    public void logPasswordResetRequest(String email) {
        logEvent("PASSWORD_RESET_REQUEST", email, "Password reset requested for email.");
    }

    public void logPasswordResetSuccess(String username) {
        logEvent("PASSWORD_RESET_SUCCESS", username, "Password successfully reset.");
    }

    public void logPasswordResetFailure(String token, String reason) {
        logEvent("PASSWORD_RESET_FAILURE", "Token: " + token, "Password reset failed. Reason: " + reason);
    }

    public void log2FASetupAttempt(String username) {
        logEvent("2FA_SETUP_ATTEMPT", username, "Attempted to set up 2FA.");
    }

    public void log2FASetupSuccess(String username) {
        logEvent("2FA_SETUP_SUCCESS", username, "2FA successfully set up.");
    }

    public void log2FAVerificationSuccess(String username) {
        logEvent("2FA_VERIFICATION_SUCCESS", username, "2FA verification successful.");
    }

    public void log2FAVerificationFailure(String username, String reason) {
        logEvent("2FA_VERIFICATION_FAILURE", username, "2FA verification failed. Reason: " + reason);
    }
}
