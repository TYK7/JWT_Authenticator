package com.example.jwtproject.service;

import com.example.jwtproject.entity.User;
import com.example.jwtproject.repository.UserRepository;
import dev.samstevens.totp.code.*;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.UUID;

@Service
public class TwoFactorAuthenticationService {

    @Autowired
    private UserRepository userRepository;

    @Value("${app.name:MyApplication}")
    private String appName;

    // In a real app, you might encrypt the secret before storing it,
    // or use a Hardware Security Module (HSM).
    // For simplicity, we'll store it as is in the User entity.

    public String generateNewSecret() {
        SecretGenerator secretGenerator = new DefaultSecretGenerator();
        return secretGenerator.generate();
    }

    public String generateQrCodeDataUri(String secret, String email) {
        QrData data = new QrData.Builder()
                .label(email) // Usually the user's email or username
                .secret(secret)
                .issuer(appName) // Your application's name
                .algorithm(HashingAlgorithm.SHA1) // SHA1 is the default for Google Authenticator
                .digits(6)
                .period(30)
                .build();

        QrGenerator generator = new ZxingPngQrGenerator();
        try {
            byte[] imageData = generator.generate(data);
            return "data:image/png;base64," + java.util.Base64.getEncoder().encodeToString(imageData);
        } catch (Exception e) {
            // Log error or throw custom exception
            throw new RuntimeException("Error generating QR code", e);
        }
    }

    @Transactional
    public String setupTwoFactorAuthentication(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found with ID: " + userId));

        if (user.isTwoFactorEnabled() && StringUtils.hasText(user.getTwoFactorSecret())) {
            // If already enabled and secret exists, perhaps return existing or re-confirm.
            // For now, let's assume we always generate a new one if requested, or one doesn't exist.
        }

        String secret = generateNewSecret();
        user.setTwoFactorSecret(secret);
        // User should verify this secret with a code before it's fully enabled.
        // For simplicity in this step, we'll set it directly.
        // A better flow: store temporary secret, user verifies, then set twoFactorEnabled = true.
        userRepository.save(user);
        return secret;
    }

    @Transactional
    public boolean enableTwoFactorAuthentication(UUID userId, String code) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found with ID: " + userId));

        if (!StringUtils.hasText(user.getTwoFactorSecret())) {
            throw new IllegalStateException("2FA secret not set up for user: " + userId);
        }

        if (verifyCode(user.getTwoFactorSecret(), code)) {
            user.setTwoFactorEnabled(true);
            userRepository.save(user);
            return true;
        }
        return false;
    }


    @Transactional
    public void disableTwoFactorAuthentication(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found with ID: " + userId));
        user.setTwoFactorEnabled(false);
        user.setTwoFactorSecret(null); // Optionally clear the secret
        userRepository.save(user);
    }


    public boolean verifyCode(String secret, String code) {
        if (!StringUtils.hasText(secret) || !StringUtils.hasText(code)) {
            return false;
        }
        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        DefaultCodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        verifier.setTimePeriod(30); // Period in seconds
        verifier.setAllowedTimePeriodDiscrepancy(1); // Number of periods of discrepancy to allow
        verifier.setTimePeriod(30); // Period in seconds
        verifier.setAllowedTimePeriodDiscrepancy(1); // Number of periods of discrepancy to allow

        return verifier.isValidCode(secret, code);
    }

    public boolean isTwoFactorEnabled(UUID userId) {
         User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found with ID: " + userId));
        return user.isTwoFactorEnabled();
    }
}
