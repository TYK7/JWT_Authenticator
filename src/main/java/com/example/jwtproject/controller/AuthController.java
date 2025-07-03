package com.example.jwtproject.controller;

import com.example.jwtproject.dto.*;
import com.example.jwtproject.entity.User;
import com.example.jwtproject.exception.BadRequestException;
import com.example.jwtproject.exception.InvalidOtpException;
import com.example.jwtproject.exception.TwoFactorAuthenticationRequiredException;
import com.example.jwtproject.service.AuditLogService;
import com.example.jwtproject.service.AuthService;
import com.example.jwtproject.service.TwoFactorAuthenticationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Map;
import java.util.UUID;

@Tag(name = "Authentication", description = "APIs for user authentication, registration, and token management")
@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private TwoFactorAuthenticationService twoFactorService;

    @Operation(summary = "Register a new user", description = "Creates a new user account.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "User registered successfully",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = User.class))),
            @ApiResponse(responseCode = "400", description = "Invalid input, username or email already exists",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegistrationRequest registrationRequest) {
        try {
            User registeredUser = authService.registerUser(registrationRequest);
            auditLogService.logRegistrationSuccess(registeredUser.getUsername());
            // Consider what to return. For security, maybe not the full user object or a simpler message.
            // For now, returning a simplified response.
            return ResponseEntity.status(HttpStatus.CREATED)
                                 .body(Map.of("message", "User registered successfully. Please check your email for verification.", "userId", registeredUser.getUserId()));
        } catch (Exception e) {
            auditLogService.logRegistrationFailure(registrationRequest.getUsername(), e.getMessage());
            throw e; // Re-throw to be handled by GlobalExceptionHandler
        }
    }

    @Operation(summary = "Login a user", description = "Authenticates a user and returns JWT tokens.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Login successful, tokens returned",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "401", description = "Invalid credentials or 2FA required",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "403", description = "2FA required, but no specific DTO for this yet, returns error response",
                                content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            AuthResponse authResponse = authService.loginUser(loginRequest);
            auditLogService.logLoginSuccess(authResponse.getUsername()); // Assuming AuthResponse has username
            return ResponseEntity.ok(authResponse);
        } catch (TwoFactorAuthenticationRequiredException e) {
            auditLogService.logLoginFailure(loginRequest.getUsernameOrEmail(), "2FA Required");
             // Custom response for 2FA required
            return ResponseEntity.status(HttpStatus.FORBIDDEN) // Or another appropriate status like 403
                                 .body(Map.of("message", e.getMessage(), "userId", e.getUserId(), "twoFactorRequired", true));
        } catch (Exception e) {
            auditLogService.logLoginFailure(loginRequest.getUsernameOrEmail(), e.getMessage());
            throw e;
        }
    }

    @Operation(summary = "Verify 2FA and complete login", description = "Verifies the 2FA code and returns JWT tokens if successful.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "2FA verification successful, tokens returned",
                content = @Content(mediaType = "application/json", schema = @Schema(implementation = AuthResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid input or 2FA code incorrect",
                content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class))),
        @ApiResponse(responseCode = "401", description = "User not found or 2FA not enabled",
                content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/login/verify-2fa")
    public ResponseEntity<?> verifyLoginWith2FA(@Valid @RequestBody TwoFactorVerificationRequest verificationRequest) {
        try {
            AuthResponse authResponse = authService.loginUserWith2FA(verificationRequest.getUserId(), verificationRequest.getCode());
            auditLogService.log2FAVerificationSuccess(authResponse.getUsername());
            auditLogService.logLoginSuccess(authResponse.getUsername()); // Also log overall login success
            return ResponseEntity.ok(authResponse);
        } catch (InvalidOtpException | UsernameNotFoundException | BadRequestException e) {
            // Log specific failure reason if possible
            String username = verificationRequest.getUserId(); // Assuming userId can act as a temporary username for logging
            try { // Attempt to get username if userId is indeed a UUID for a user
                User u = authService.getUserById(UUID.fromString(verificationRequest.getUserId())); // Requires a method in AuthService
                if (u != null) username = u.getUsername();
            } catch (Exception ignored) {}

            auditLogService.log2FAVerificationFailure(username, e.getMessage());
            auditLogService.logLoginFailure(username, "2FA verification failed: " + e.getMessage());
            throw e;
        }
    }


    @Operation(summary = "Refresh JWT access token", description = "Obtains a new access token using a refresh token.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token refreshed successfully",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = TokenResponse.class))),
            @ApiResponse(responseCode = "400", description = "Invalid refresh token",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.badRequest().body(new ErrorResponse(null, HttpStatus.BAD_REQUEST.value(), "Bad Request", "Refresh token is required.", "/auth/refresh-token"));
        }
        // Username can be extracted from token for logging, but be careful if token is invalid
        String usernameForLog = "unknown";
        try {
            // Attempt to get username before validation for logging, handle potential errors
            if (authService.isTokenPotentiallyValid(refreshToken)) { // Add a light check in AuthService or JwtUtil if needed
                 usernameForLog = authService.getUsernameFromToken(refreshToken); // Requires method in AuthService or direct JwtUtil usage
            }
            TokenResponse tokenResponse = authService.refreshToken(refreshToken);
            auditLogService.logTokenRefreshSuccess(usernameForLog);
            return ResponseEntity.ok(tokenResponse);
        } catch (Exception e) {
            auditLogService.logTokenRefreshFailure(usernameForLog, e.getMessage());
            throw e;
        }
    }

    @Operation(summary = "Request a password reset", description = "Initiates the password reset process by sending an email to the user.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Password reset email sent (if user exists)."),
        @ApiResponse(responseCode = "400", description = "Invalid email format.",
                content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class))),
        @ApiResponse(responseCode = "404", description = "User with the given email not found.",
                content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/request-password-reset")
    public ResponseEntity<?> requestPasswordReset(@Valid @RequestBody PasswordResetRequest passwordResetRequest) {
        try {
            authService.initiatePasswordReset(passwordResetRequest.getEmail());
            auditLogService.logPasswordResetRequest(passwordResetRequest.getEmail());
            return ResponseEntity.ok(Map.of("message", "If an account with that email exists, a password reset link has been sent."));
        } catch (UsernameNotFoundException e) { // Catch specific exception for not found
             auditLogService.logPasswordResetRequest(passwordResetRequest.getEmail()); // Log attempt even if user not found
             return ResponseEntity.ok(Map.of("message", "If an account with that email exists, a password reset link has been sent.")); // Generic message for security
        } catch (Exception e) {
            // Log other errors if necessary, but typically keep response generic for this endpoint
            auditLogService.logPasswordResetRequest(passwordResetRequest.getEmail()); // Log attempt
            throw e;
        }
    }

    @Operation(summary = "Reset user password", description = "Resets the user's password using a valid reset token.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Password has been reset successfully."),
        @ApiResponse(responseCode = "400", description = "Invalid token or password format.",
                content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody PasswordResetConfirmationRequest request) {
        try {
            authService.confirmPasswordReset(request.getToken(), request.getNewPassword());
            // Username is not directly available here unless fetched from token, log generically or fetch user if needed.
            auditLogService.logPasswordResetSuccess("User (token: " + request.getToken().substring(0, Math.min(8, request.getToken().length())) + "...)");
            return ResponseEntity.ok(Map.of("message", "Your password has been reset successfully."));
        } catch (Exception e) {
            auditLogService.logPasswordResetFailure(request.getToken(), e.getMessage());
            throw e;
        }
    }

    @Operation(summary = "Verify user email", description = "Verifies a user's email address using a verification token.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Email verified successfully."),
        @ApiResponse(responseCode = "400", description = "Invalid or expired verification token.",
                content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class)))
    })
    @GetMapping("/verify-email") // Typically GET for link-based verification
    public ResponseEntity<?> verifyEmail(@RequestParam("token") String token) {
        // This is a conceptual endpoint. In a real app, the token would be validated,
        // user status updated, and then redirect to a login or success page.
        try {
            User user = authService.verifyEmail(token); // Assuming token is user ID for simplicity now
            return ResponseEntity.ok(Map.of("message", "Email verified successfully for user: " + user.getUsername()));
        } catch (Exception e) {
            throw e;
        }
    }

    @Operation(summary = "Setup 2FA for the logged-in user", description = "Generates a new 2FA secret and QR code URI for the authenticated user.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "2FA setup details returned",
                content = @Content(mediaType = "application/json", schema = @Schema(implementation = TwoFactorSetupResponse.class))),
        @ApiResponse(responseCode = "401", description = "User not authenticated")
    })
    @PostMapping("/setup-2fa")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> setupTwoFactorAuthentication(Principal principal) {
        User user = authService.getUserByUsername(principal.getName()); // Requires method in AuthService
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not found or not authenticated.");
        }

        auditLogService.log2FASetupAttempt(user.getUsername());
        String secret = twoFactorService.setupTwoFactorAuthentication(user.getUserId());
        String qrCodeUri = twoFactorService.generateQrCodeDataUri(secret, user.getEmail());

        // Note: 2FA is not yet enabled. User needs to verify with a code.
        return ResponseEntity.ok(new TwoFactorSetupResponse(secret, qrCodeUri, false));
    }

    @Operation(summary = "Enable 2FA by verifying a code", description = "Verifies the 2FA code and enables 2FA for the authenticated user if the code is correct.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "2FA enabled successfully."),
        @ApiResponse(responseCode = "400", description = "Invalid 2FA code or 2FA secret not set up.",
                content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class))),
        @ApiResponse(responseCode = "401", description = "User not authenticated")
    })
    @PostMapping("/enable-2fa")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> enableTwoFactorAuthentication(@Valid @RequestBody Map<String, String> payload, Principal principal) {
        String code = payload.get("code");
        if (code == null || code.isBlank()) {
            throw new BadRequestException("2FA code is required.");
        }

        User user = authService.getUserByUsername(principal.getName());
         if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not found or not authenticated.");
        }

        try {
            boolean success = twoFactorService.enableTwoFactorAuthentication(user.getUserId(), code);
            if (success) {
                auditLogService.log2FASetupSuccess(user.getUsername());
                return ResponseEntity.ok(Map.of("message", "Two-factor authentication enabled successfully."));
            } else {
                auditLogService.log2FAVerificationFailure(user.getUsername(), "Invalid 2FA code during enable process.");
                throw new InvalidOtpException("Invalid 2FA code.");
            }
        } catch (Exception e) {
            auditLogService.log2FAVerificationFailure(user.getUsername(), e.getMessage());
            throw e;
        }
    }

    @Operation(summary = "Disable 2FA for the logged-in user", description = "Disables two-factor authentication for the authenticated user.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "2FA disabled successfully."),
        @ApiResponse(responseCode = "401", description = "User not authenticated")
    })
    @PostMapping("/disable-2fa")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> disableTwoFactorAuthentication(Principal principal) {
        User user = authService.getUserByUsername(principal.getName());
         if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not found or not authenticated.");
        }

        twoFactorService.disableTwoFactorAuthentication(user.getUserId());
        auditLogService.logEvent("2FA_DISABLE_SUCCESS", user.getUsername(), "2FA disabled by user.");
        return ResponseEntity.ok(Map.of("message", "Two-factor authentication disabled successfully."));
    }


    // This is effectively the same as /auth/login then /auth/token.
    // Kept for fulfilling requirement but login endpoint is more standard.
    @Operation(summary = "Get JWT token after authentication", description = "Validates credentials and returns JWT tokens. Similar to /login but specifically for token retrieval post-authentication (if needed by a specific flow).")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Tokens returned",
                content = @Content(mediaType = "application/json", schema = @Schema(implementation = TokenResponse.class))),
        @ApiResponse(responseCode = "401", description = "Invalid credentials",
                content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/token")
    public ResponseEntity<?> getToken(@Valid @RequestBody LoginRequest loginRequest) {
         // This endpoint behaves very similarly to /login.
         // If 2FA is enabled, it should also follow the 2FA flow.
        try {
            AuthResponse authResponse = authService.loginUser(loginRequest); // Reuses the login logic
            auditLogService.logTokenIssued(authResponse.getUsername(), "Access & Refresh Token (via /token)");
            // Return a simpler TokenResponse if only tokens are expected from /auth/token
            return ResponseEntity.ok(new TokenResponse(authResponse.getAccessToken(), authResponse.getRefreshToken(), authResponse.getExpiresIn()));
        } catch (TwoFactorAuthenticationRequiredException e) {
             auditLogService.logLoginFailure(loginRequest.getUsernameOrEmail(), "2FA Required for /token endpoint");
             return ResponseEntity.status(HttpStatus.FORBIDDEN)
                                  .body(Map.of("message", e.getMessage(), "userId", e.getUserId(), "twoFactorRequired", true));
        } catch (Exception e) {
            auditLogService.logLoginFailure(loginRequest.getUsernameOrEmail(), e.getMessage() + " (on /token endpoint)");
            throw e;
        }
    }
}
