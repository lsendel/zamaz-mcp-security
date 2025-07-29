package com.zamaz.mcp.security.service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import com.zamaz.mcp.security.entity.User;
import com.zamaz.mcp.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Multi-Factor Authentication service supporting TOTP, backup codes, and
 * hardware tokens.
 * Implements modern MFA standards with recovery mechanisms.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class MfaService {

    private final UserRepository userRepository;
    private final GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator();
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${app.name:Zamaz MCP}")
    private String applicationName;

    @Value("${security.mfa.backup-codes.count:10}")
    private int backupCodesCount;

    @Value("${security.mfa.totp.window:3}")
    private int totpTimeWindow;

    /**
     * Enable MFA for a user by generating TOTP secret and backup codes.
     */
    @Transactional
    public MfaSetupResult enableMfa(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (user.getMfaEnabled()) {
            throw new IllegalStateException("MFA is already enabled for this user");
        }

        // Generate TOTP secret
        GoogleAuthenticatorKey key = googleAuthenticator.createCredentials();
        String secret = key.getKey();

        // Generate backup codes
        List<String> backupCodes = generateBackupCodes();

        // Update user
        user.setMfaSecret(secret);
        user.setMfaBackupCodes(String.join(",", backupCodes));
        user.setMfaRecoveryCodesUsed(0);
        // Don't enable MFA yet - user needs to verify first
        userRepository.save(user);

        // Generate QR code
        String qrCodeUrl = GoogleAuthenticatorQRGenerator.getOtpAuthURL(
                applicationName,
                user.getEmail(),
                key);

        byte[] qrCodeImage = generateQrCodeImage(qrCodeUrl);

        log.info("MFA setup initiated for user: {}", user.getEmail());

        return new MfaSetupResult(secret, qrCodeUrl, qrCodeImage, backupCodes);
    }

    /**
     * Verify MFA setup by validating the first TOTP code.
     */
    @Transactional
    public boolean verifyMfaSetup(UUID userId, String totpCode) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (user.getMfaSecret() == null) {
            throw new IllegalStateException("MFA setup not initiated");
        }

        if (user.getMfaEnabled()) {
            throw new IllegalStateException("MFA is already enabled");
        }

        // Verify TOTP code
        boolean isValid = googleAuthenticator.authorize(user.getMfaSecret(), Integer.parseInt(totpCode));

        if (isValid) {
            user.setMfaEnabled(true);
            userRepository.save(user);
            log.info("MFA enabled for user: {}", user.getEmail());
            return true;
        }

        log.warn("Invalid MFA verification code for user: {}", user.getEmail());
        return false;
    }

    /**
     * Verify MFA code (TOTP or backup code).
     */
    @Transactional
    public MfaVerificationResult verifyMfa(UUID userId, String code) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!user.getMfaEnabled()) {
            return new MfaVerificationResult(false, MfaVerificationResult.FailureReason.MFA_NOT_ENABLED);
        }

        // Try TOTP first
        try {
            int totpCode = Integer.parseInt(code);
            if (googleAuthenticator.authorize(user.getMfaSecret(), totpCode)) {
                log.debug("TOTP verification successful for user: {}", user.getEmail());
                return new MfaVerificationResult(true, null);
            }
        } catch (NumberFormatException e) {
            // Not a numeric code, might be a backup code
        }

        // Try backup codes
        if (user.getMfaBackupCodes() != null) {
            List<String> backupCodes = List.of(user.getMfaBackupCodes().split(","));
            if (backupCodes.contains(code)) {
                // Remove used backup code
                List<String> remainingCodes = new ArrayList<>(backupCodes);
                remainingCodes.remove(code);
                user.setMfaBackupCodes(String.join(",", remainingCodes));
                user.setMfaRecoveryCodesUsed(user.getMfaRecoveryCodesUsed() + 1);
                userRepository.save(user);

                log.info("Backup code used for user: {} (remaining: {})",
                        user.getEmail(), remainingCodes.size());

                return new MfaVerificationResult(true, null);
            }
        }

        log.warn("MFA verification failed for user: {}", user.getEmail());
        return new MfaVerificationResult(false, MfaVerificationResult.FailureReason.INVALID_CODE);
    }

    /**
     * Disable MFA for a user.
     */
    @Transactional
    public void disableMfa(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        user.setMfaEnabled(false);
        user.setMfaSecret(null);
        user.setMfaBackupCodes(null);
        user.setMfaRecoveryCodesUsed(0);
        userRepository.save(user);

        log.info("MFA disabled for user: {}", user.getEmail());
    }

    /**
     * Generate new backup codes for a user.
     */
    @Transactional
    public List<String> regenerateBackupCodes(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!user.getMfaEnabled()) {
            throw new IllegalStateException("MFA is not enabled for this user");
        }

        List<String> newBackupCodes = generateBackupCodes();
        user.setMfaBackupCodes(String.join(",", newBackupCodes));
        user.setMfaRecoveryCodesUsed(0);
        userRepository.save(user);

        log.info("Backup codes regenerated for user: {}", user.getEmail());
        return newBackupCodes;
    }

    /**
     * Get MFA status for a user.
     */
    public MfaStatus getMfaStatus(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        int remainingBackupCodes = 0;
        if (user.getMfaBackupCodes() != null) {
            remainingBackupCodes = user.getMfaBackupCodes().split(",").length;
        }

        return new MfaStatus(
                user.getMfaEnabled(),
                user.getMfaSecret() != null,
                remainingBackupCodes,
                user.getMfaRecoveryCodesUsed());
    }

    /**
     * Generate secure backup codes.
     */
    private List<String> generateBackupCodes() {
        List<String> codes = new ArrayList<>();
        for (int i = 0; i < backupCodesCount; i++) {
            // Generate 8-character alphanumeric code
            StringBuilder code = new StringBuilder();
            String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            for (int j = 0; j < 8; j++) {
                code.append(chars.charAt(secureRandom.nextInt(chars.length())));
            }
            codes.add(code.toString());
        }
        return codes;
    }

    /**
     * Generate QR code image for TOTP setup.
     */
    private byte[] generateQrCodeImage(String qrCodeUrl) {
        try {
            QRCodeWriter qrCodeWriter = new QRCodeWriter();
            BitMatrix bitMatrix = qrCodeWriter.encode(qrCodeUrl, BarcodeFormat.QR_CODE, 200, 200);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);
            return outputStream.toByteArray();

        } catch (Exception e) {
            log.error("Failed to generate QR code", e);
            return new byte[0];
        }
    }

    /**
     * MFA setup result containing all necessary information for user setup.
     */
    public static class MfaSetupResult {
        private final String secret;
        private final String qrCodeUrl;
        private final byte[] qrCodeImage;
        private final List<String> backupCodes;

        public MfaSetupResult(String secret, String qrCodeUrl, byte[] qrCodeImage, List<String> backupCodes) {
            this.secret = secret;
            this.qrCodeUrl = qrCodeUrl;
            this.qrCodeImage = qrCodeImage;
            this.backupCodes = backupCodes;
        }

        public String getSecret() {
            return secret;
        }

        public String getQrCodeUrl() {
            return qrCodeUrl;
        }

        public byte[] getQrCodeImage() {
            return qrCodeImage;
        }

        public String getQrCodeImageBase64() {
            return Base64.getEncoder().encodeToString(qrCodeImage);
        }

        public List<String> getBackupCodes() {
            return backupCodes;
        }
    }

    /**
     * MFA verification result.
     */
    public static class MfaVerificationResult {
        private final boolean valid;
        private final FailureReason failureReason;

        public MfaVerificationResult(boolean valid, FailureReason failureReason) {
            this.valid = valid;
            this.failureReason = failureReason;
        }

        public boolean isValid() {
            return valid;
        }

        public FailureReason getFailureReason() {
            return failureReason;
        }

        public enum FailureReason {
            MFA_NOT_ENABLED,
            INVALID_CODE,
            EXPIRED_CODE
        }
    }

    /**
     * MFA status information.
     */
    public static class MfaStatus {
        private final boolean enabled;
        private final boolean setupInProgress;
        private final int remainingBackupCodes;
        private final int usedBackupCodes;

        public MfaStatus(boolean enabled, boolean setupInProgress, int remainingBackupCodes, int usedBackupCodes) {
            this.enabled = enabled;
            this.setupInProgress = setupInProgress;
            this.remainingBackupCodes = remainingBackupCodes;
            this.usedBackupCodes = usedBackupCodes;
        }

        public boolean isEnabled() {
            return enabled;
        }

        public boolean isSetupInProgress() {
            return setupInProgress;
        }

        public int getRemainingBackupCodes() {
            return remainingBackupCodes;
        }

        public int getUsedBackupCodes() {
            return usedBackupCodes;
        }

        public boolean needsBackupCodeRefresh() {
            return remainingBackupCodes < 3;
        }
    }
}