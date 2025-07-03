package com.example.jwtproject.service;

import com.example.jwtproject.dto.AuthResponse;
import com.example.jwtproject.dto.LoginRequest;
import com.example.jwtproject.dto.RegistrationRequest;
import com.example.jwtproject.dto.TokenResponse;
import com.example.jwtproject.entity.PasswordResetToken;
import com.example.jwtproject.entity.User;
import com.example.jwtproject.exception.*;
import com.example.jwtproject.repository.PasswordResetTokenRepository;
import com.example.jwtproject.repository.UserRepository;
import com.example.jwtproject.security.JwtUtil;
import com.example.jwtproject.security.UserDetailsImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private EmailService emailService; // For sending verification and password reset emails

    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @Autowired
    private TwoFactorAuthenticationService twoFactorService;


    @Transactional
    public User registerUser(RegistrationRequest registrationRequest) {
        if (userRepository.existsByUsername(registrationRequest.getUsername())) {
            throw new UsernameAlreadyExistsException("Username " + registrationRequest.getUsername() + " is already taken!");
        }
        if (userRepository.existsByEmail(registrationRequest.getEmail())) {
            throw new EmailAlreadyExistsException("Email " + registrationRequest.getEmail() + " is already in use!");
        }

        User user = User.builder()
                .username(registrationRequest.getUsername())
                .email(registrationRequest.getEmail())
                .password(passwordEncoder.encode(registrationRequest.getPassword()))
                .role(registrationRequest.getRole())
                .location(registrationRequest.getLocation())
                .tenantId(registrationRequest.getTenantId()) // Multi-tenancy support
                .emailVerified(false) // Email not verified initially
                .twoFactorEnabled(false)
                .availableTokens(1000) // Default available tokens
                .build();

        // In a real app, generate a verification token, save it, and send email.
        // String verificationToken = UUID.randomUUID().toString();
        // user.setVerificationToken(verificationToken); // Add this field to User entity if needed

        User registeredUser = userRepository.save(user);
        logger.info("User registered successfully: {}", registeredUser.getUsername());

        // Simulate sending verification email
        // emailService.sendVerificationEmail(registeredUser.getEmail(), registeredUser.getUsername(), verificationToken);
        // For now, we'll skip actual email sending and token persistence for verification in this step
        // and assume auto-verification or a separate endpoint for it.
        // To make user enabled after registration for testing, we can set emailVerified to true.
        // registeredUser.setEmailVerified(true); // TEMPORARY FOR TESTING WITHOUT EMAIL VERIFICATION
        // userRepository.save(registeredUser); // Save again if modified

        return registeredUser;
    }

    @Transactional
    public AuthResponse loginUser(LoginRequest loginRequest) {
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsernameOrEmail(), loginRequest.getPassword()));
        } catch (BadCredentialsException e) {
            logger.warn("Login attempt failed for user: {}", loginRequest.getUsernameOrEmail());
            throw new InvalidCredentialsException("Invalid username/email or password");
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        // Check if 2FA is enabled for the user
        if (twoFactorService.isTwoFactorEnabled(userDetails.getId())) {
            // If 2FA is enabled, don't issue tokens yet.
            // The client should be prompted for a 2FA code.
            // This response indicates that 2FA is required.
            // A real implementation might return a specific status or DTO.
            logger.info("2FA required for user: {}", userDetails.getUsername());
            throw new TwoFactorAuthenticationRequiredException("2FA code required for user: " + userDetails.getUsername(), userDetails.getId().toString());
        }

        // If 2FA is not enabled or already passed (e.g. via a separate 2FA verification step that sets a temporary auth)
        String accessToken = jwtUtil.generateAccessToken(authentication);
        String refreshToken = jwtUtil.generateRefreshToken(authentication);
        long expiresIn = jwtUtil.getAccessTokenExpirationMs() / 1000;


        logger.info("User {} logged in successfully.", userDetails.getUsername());
        return new AuthResponse(accessToken, refreshToken, expiresIn, userDetails.getId(), userDetails.getUsername(), userDetails.getEmail(), userDetails.getAuthorities().iterator().next().getAuthority());
    }

    @Transactional
    public AuthResponse loginUserWith2FA(String userId, String code) {
        UUID userUUID = UUID.fromString(userId);
        User user = userRepository.findById(userUUID)
            .orElseThrow(() -> new UserNotFoundException("User not found with ID: " + userId));

        if (!user.isTwoFactorEnabled()) {
            throw new BadRequestException("2FA is not enabled for this user.");
        }

        if (!twoFactorService.verifyCode(user.getTwoFactorSecret(), code)) {
            throw new InvalidOtpException("Invalid 2FA code.");
        }

        // If 2FA code is valid, proceed to generate tokens
        // We need to create an Authentication object for the user
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String accessToken = jwtUtil.generateAccessToken(user); // Use user object directly
        String refreshToken = jwtUtil.generateRefreshToken(user); // Use user object directly
        long expiresIn = jwtUtil.getAccessTokenExpirationMs() / 1000;

        logger.info("User {} logged in successfully with 2FA.", user.getUsername());
        return new AuthResponse(accessToken, refreshToken, expiresIn, user.getUserId(), user.getUsername(), user.getEmail(), user.getRole().name());
    }


    @Transactional
    public TokenResponse refreshToken(String oldRefreshToken) {
        if (!jwtUtil.validateJwtToken(oldRefreshToken)) {
            throw new TokenRefreshException(oldRefreshToken, "Invalid refresh token!");
        }

        String username = jwtUtil.getUsernameFromJwtToken(oldRefreshToken);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found with username: " + username));

        // Here you might want to check if the refresh token is blacklisted or if user status changed.
        // For simplicity, we directly issue a new access token.

        String newAccessToken = jwtUtil.generateAccessToken(user);
        long expiresIn = jwtUtil.getAccessTokenExpirationMs() / 1000;

        // Optionally, generate a new refresh token as well (recommended for security)
        String newRefreshToken = jwtUtil.generateRefreshToken(user);

        logger.info("Access token refreshed for user: {}", username);
        return new TokenResponse(newAccessToken, newRefreshToken, expiresIn);
    }


    @Transactional
    public void initiatePasswordReset(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found with email: " + email));

        // Invalidate previous tokens for this user
        passwordResetTokenRepository.findByUser(user).ifPresent(passwordResetTokenRepository::delete);

        String token = UUID.randomUUID().toString();
        PasswordResetToken passwordResetToken = new PasswordResetToken(user, token);
        passwordResetTokenRepository.save(passwordResetToken);

        emailService.sendPasswordResetEmail(user.getEmail(), user.getUsername(), token);
        logger.info("Password reset initiated for user: {}", email);
    }

    @Transactional
    public void confirmPasswordReset(String token, String newPassword) {
        PasswordResetToken passwordResetToken = passwordResetTokenRepository.findByToken(token)
                .orElseThrow(() -> new InvalidTokenException("Invalid or expired password reset token."));

        if (passwordResetToken.isExpired()) {
            passwordResetTokenRepository.delete(passwordResetToken);
            throw new InvalidTokenException("Password reset token has expired.");
        }

        User user = passwordResetToken.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        passwordResetTokenRepository.delete(passwordResetToken); // Token is used, delete it
        logger.info("Password reset successfully for user: {}", user.getUsername());
    }

    @Transactional
    public User verifyEmail(String token) {
        // This is a simplified version.
        // In a real app, you'd have a separate EmailVerificationToken entity similar to PasswordResetToken.
        // For now, let's assume the token is the user's ID for direct verification for simplicity.
        try {
            UUID userId = UUID.fromString(token); // Assuming token is User ID for this example
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new InvalidTokenException("Invalid verification token. User not found."));

            if (user.isEmailVerified()) {
                throw new AlreadyVerifiedException("Email already verified for user: " + user.getUsername());
            }

            user.setEmailVerified(true);
            userRepository.save(user);
            logger.info("Email verified successfully for user: {}", user.getUsername());
            return user;
        } catch (IllegalArgumentException e) {
            throw new InvalidTokenException("Invalid verification token format.");
        }
    }
}
