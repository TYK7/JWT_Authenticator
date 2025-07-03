package com.example.jwtproject.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private static final Logger logger = LoggerFactory.getLogger(EmailService.class);

    // In a real application, you would integrate with an email sending library
    // (e.g., Spring Mail, SendGrid, AWS SES)

    public void sendVerificationEmail(String toEmail, String username, String verificationToken) {
        // Simulate email sending
        String verificationLink = "http://localhost:8080/auth/verify-email?token=" + verificationToken;
        logger.info("---- EMAIL SIMULATION ----");
        logger.info("To: {}", toEmail);
        logger.info("Subject: Verify Your Email Address");
        logger.info("Body: Hello {}, please verify your email by clicking the link: {}", username, verificationLink);
        logger.info("--------------------------");
        // In a real scenario, you'd use an email template and actual sending logic.
    }

    public void sendPasswordResetEmail(String toEmail, String username, String resetToken) {
        // Simulate email sending
        // Note: The link should point to a frontend page that then calls the backend API with the token
        String resetLink = "http://localhost:3000/reset-password?token=" + resetToken; // Example frontend link
        logger.info("---- EMAIL SIMULATION ----");
        logger.info("To: {}", toEmail);
        logger.info("Subject: Password Reset Request");
        logger.info("Body: Hello {}, you requested a password reset. Click the link to reset your password: {}", username, resetLink);
        logger.info("If you did not request this, please ignore this email.");
        logger.info("--------------------------");
    }

    public void sendTwoFactorCodeEmail(String toEmail, String username, String twoFactorCode) {
        // Simulate email sending for 2FA code if email is chosen as a 2FA method
        logger.info("---- EMAIL SIMULATION ----");
        logger.info("To: {}", toEmail);
        logger.info("Subject: Your Two-Factor Authentication Code");
        logger.info("Body: Hello {}, your 2FA code is: {}. It is valid for a short period.", username, twoFactorCode);
        logger.info("--------------------------");
    }

    public void sendAccountRecoveryEmail(String toEmail, String username, String recoveryLink) {
        logger.info("---- EMAIL SIMULATION ----");
        logger.info("To: {}", toEmail);
        logger.info("Subject: Account Recovery Information");
        logger.info("Body: Hello {}, to recover your account, please click the following link: {}", username, recoveryLink);
        logger.info("--------------------------");
    }
}
