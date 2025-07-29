package com.zamaz.mcp.security.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Externalized security configuration properties.
 * Allows security settings to be managed through configuration management
 * without code changes.
 */
@Data
@Component
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {

    private Jwt jwt = new Jwt();
    private Cors cors = new Cors();
    private Headers headers = new Headers();
    private Password password = new Password();
    private Mfa mfa = new Mfa();
    private Lockout lockout = new Lockout();
    private Alerts alerts = new Alerts();

    @Data
    public static class Jwt {
        private String issuer = "mcp-auth-server";
        private String signingAlgorithm = "RS256";
        private int accessTokenExpirationMinutes = 15;
        private int refreshTokenExpirationDays = 30;
        private boolean enableTokenRotation = true;
        private String keyStoreLocation;
        private String keyStorePassword;
        private String keyAlias;
    }

    @Data
    public static class Cors {
        private List<String> allowedOrigins = List.of("http://localhost:3000", "http://localhost:8080");
        private List<String> allowedMethods = List.of("GET", "POST", "PUT", "DELETE", "OPTIONS");
        private List<String> allowedHeaders = List.of("*");
        private boolean allowCredentials = true;
        private long maxAge = 3600;
    }

    @Data
    public static class Headers {
        private String contentSecurityPolicy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:; frame-ancestors 'none';";
        private String referrerPolicy = "strict-origin-when-cross-origin";
        private String permissionsPolicy = "geolocation=(), microphone=(), camera=()";
        private boolean enableHsts = true;
        private long hstsMaxAge = 31536000;
        private boolean hstsIncludeSubdomains = true;
        private boolean hstsPreload = true;
    }

    @Data
    public static class Password {
        private int minLength = 12;
        private int maxLength = 128;
        private BreachCheck breachCheck = new BreachCheck();

        @Data
        public static class BreachCheck {
            private boolean enabled = true;
            private String apiUrl = "https://api.pwnedpasswords.com/range/";
            private int timeoutSeconds = 5;
        }
    }

    @Data
    public static class Mfa {
        private BackupCodes backupCodes = new BackupCodes();
        private Totp totp = new Totp();

        @Data
        public static class BackupCodes {
            private int count = 10;
            private int length = 8;
        }

        @Data
        public static class Totp {
            private int window = 3;
            private int codeDigits = 6;
            private int timeStepSeconds = 30;
        }
    }

    @Data
    public static class Lockout {
        private int maxAttempts = 5;
        private int initialDurationMinutes = 5;
        private int maxDurationMinutes = 1440; // 24 hours
        private int progressiveMultiplier = 2;
        private boolean enableProgressiveDelay = true;
    }

    @Data
    public static class Alerts {
        private boolean enabled = true;
        private Webhook webhook = new Webhook();
        private Email email = new Email();
        private Thresholds thresholds = new Thresholds();

        @Data
        public static class Webhook {
            private String url;
            private int timeoutSeconds = 10;
            private int retryAttempts = 3;
        }

        @Data
        public static class Email {
            private boolean enabled = false;
            private List<String> recipients = List.of();
            private String fromAddress = "security@zamaz.com";
        }

        @Data
        public static class Thresholds {
            private int failedLoginThreshold = 5;
            private int suspiciousIpThreshold = 10;
            private int highRiskEventThreshold = 3;
            private int analysisWindowMinutes = 15;
        }
    }
}