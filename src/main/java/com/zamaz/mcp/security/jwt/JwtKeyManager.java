package com.zamaz.mcp.security.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

/**
 * JWT Key Management service supporting both HMAC and RSA key types.
 * Implements proper key rotation and secure storage mechanisms.
 */
@Component
@Slf4j
public class JwtKeyManager {

    @Value("${jwt.signing.algorithm:HS256}")
    private String signingAlgorithm;

    @Value("${jwt.secret:}")
    private String hmacSecret;

    @Value("${jwt.rsa.private-key:}")
    private String rsaPrivateKey;

    @Value("${jwt.rsa.public-key:}")
    private String rsaPublicKey;

    @Value("${jwt.key.rotation.enabled:false}")
    private boolean keyRotationEnabled;

    private SecretKey hmacKey;
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;
    private KeyPair keyPair;

    @PostConstruct
    public void initializeKeys() {
        log.info("Initializing JWT keys with algorithm: {}", signingAlgorithm);

        if ("RS256".equals(signingAlgorithm)) {
            initializeRSAKeys();
        } else {
            initializeHMACKeys();
        }
    }

    private void initializeHMACKeys() {
        if (hmacSecret == null || hmacSecret.trim().isEmpty()) {
            log.warn("No HMAC secret provided, generating random key for development");
            this.hmacKey = Jwts.SIG.HS256.key().build();
        } else {
            this.hmacKey = Keys.hmacShaKeyFor(hmacSecret.getBytes(StandardCharsets.UTF_8));
        }
        log.info("HMAC key initialized successfully");
    }

    private void initializeRSAKeys() {
        try {
            if (rsaPrivateKey != null && !rsaPrivateKey.trim().isEmpty() &&
                    rsaPublicKey != null && !rsaPublicKey.trim().isEmpty()) {
                // Load keys from configuration
                loadRSAKeysFromConfig();
            } else {
                // Generate new RSA key pair for development
                log.warn("No RSA keys provided, generating new key pair for development");
                generateRSAKeyPair();
            }
            log.info("RSA keys initialized successfully");
        } catch (Exception e) {
            log.error("Failed to initialize RSA keys", e);
            throw new IllegalStateException("Failed to initialize RSA keys", e);
        }
    }

    private void loadRSAKeysFromConfig() {
        try {
            // Remove PEM headers and decode base64
            String privateKeyContent = rsaPrivateKey
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            String publicKeyContent = rsaPublicKey
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyContent);
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyContent);

            java.security.spec.PKCS8EncodedKeySpec privateKeySpec = new java.security.spec.PKCS8EncodedKeySpec(
                    privateKeyBytes);
            java.security.spec.X509EncodedKeySpec publicKeySpec = new java.security.spec.X509EncodedKeySpec(
                    publicKeyBytes);

            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            this.privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
            this.publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

        } catch (Exception e) {
            log.error("Failed to load RSA keys from configuration", e);
            throw new IllegalStateException("Failed to load RSA keys from configuration", e);
        }
    }

    private void generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        this.keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
        this.publicKey = (RSAPublicKey) keyPair.getPublic();
    }

    /**
     * Get the signing key based on the configured algorithm.
     */
    public Object getSigningKey() {
        if ("RS256".equals(signingAlgorithm)) {
            return privateKey;
        } else {
            return hmacKey;
        }
    }

    /**
     * Get the verification key based on the configured algorithm.
     */
    public Object getVerificationKey() {
        if ("RS256".equals(signingAlgorithm)) {
            return publicKey;
        } else {
            return hmacKey;
        }
    }

    /**
     * Get the signing algorithm.
     */
    public String getSigningAlgorithm() {
        return signingAlgorithm;
    }

    /**
     * Check if RSA keys are being used.
     */
    public boolean isUsingRSA() {
        return "RS256".equals(signingAlgorithm);
    }

    /**
     * Get RSA public key for JWK set (used by authorization server).
     */
    public RSAPublicKey getRSAPublicKey() {
        return publicKey;
    }

    /**
     * Get RSA private key for signing (used by authorization server).
     */
    public RSAPrivateKey getRSAPrivateKey() {
        return privateKey;
    }

    /**
     * Rotate keys if rotation is enabled.
     */
    public void rotateKeys() {
        if (!keyRotationEnabled) {
            log.debug("Key rotation is disabled");
            return;
        }

        log.info("Rotating JWT keys");
        try {
            if ("RS256".equals(signingAlgorithm)) {
                generateRSAKeyPair();
            } else {
                this.hmacKey = Jwts.SIG.HS256.key().build();
            }
            log.info("JWT keys rotated successfully");
        } catch (Exception e) {
            log.error("Failed to rotate JWT keys", e);
            throw new IllegalStateException("Failed to rotate JWT keys", e);
        }
    }
}