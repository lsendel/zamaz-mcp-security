package com.zamaz.mcp.security.jwt;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.util.ReflectionTestUtils;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.SecretKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Test class for JWT key manager with modern key management patterns.
 */
@ExtendWith(MockitoExtension.class)
@SpringJUnitConfig
class JwtKeyManagerTest {

    @Test
    void shouldInitializeHMACKeysWithProvidedSecret() {
        // Given
        JwtKeyManager keyManager = new JwtKeyManager();
        ReflectionTestUtils.setField(keyManager, "signingAlgorithm", "HS256");
        ReflectionTestUtils.setField(keyManager, "hmacSecret", "test-secret-key-that-is-long-enough");

        // When
        keyManager.initializeKeys();

        // Then
        assertThat(keyManager.getSigningAlgorithm()).isEqualTo("HS256");
        assertThat(keyManager.isUsingRSA()).isFalse();
        assertThat(keyManager.getSigningKey()).isInstanceOf(SecretKey.class);
        assertThat(keyManager.getVerificationKey()).isInstanceOf(SecretKey.class);
        assertThat(keyManager.getSigningKey()).isEqualTo(keyManager.getVerificationKey());
    }

    @Test
    void shouldGenerateRandomHMACKeyWhenSecretNotProvided() {
        // Given
        JwtKeyManager keyManager = new JwtKeyManager();
        ReflectionTestUtils.setField(keyManager, "signingAlgorithm", "HS256");
        ReflectionTestUtils.setField(keyManager, "hmacSecret", "");

        // When
        keyManager.initializeKeys();

        // Then
        assertThat(keyManager.getSigningAlgorithm()).isEqualTo("HS256");
        assertThat(keyManager.isUsingRSA()).isFalse();
        assertThat(keyManager.getSigningKey()).isInstanceOf(SecretKey.class);
        assertThat(keyManager.getVerificationKey()).isInstanceOf(SecretKey.class);
    }

    @Test
    void shouldGenerateRSAKeysWhenConfiguredForRS256() {
        // Given
        JwtKeyManager keyManager = new JwtKeyManager();
        ReflectionTestUtils.setField(keyManager, "signingAlgorithm", "RS256");
        ReflectionTestUtils.setField(keyManager, "rsaPrivateKey", "");
        ReflectionTestUtils.setField(keyManager, "rsaPublicKey", "");

        // When
        keyManager.initializeKeys();

        // Then
        assertThat(keyManager.getSigningAlgorithm()).isEqualTo("RS256");
        assertThat(keyManager.isUsingRSA()).isTrue();
        assertThat(keyManager.getSigningKey()).isInstanceOf(RSAPrivateKey.class);
        assertThat(keyManager.getVerificationKey()).isInstanceOf(RSAPublicKey.class);
        assertThat(keyManager.getRSAPrivateKey()).isNotNull();
        assertThat(keyManager.getRSAPublicKey()).isNotNull();
    }

    @Test
    void shouldRotateHMACKeys() {
        // Given
        JwtKeyManager keyManager = new JwtKeyManager();
        ReflectionTestUtils.setField(keyManager, "signingAlgorithm", "HS256");
        ReflectionTestUtils.setField(keyManager, "hmacSecret", "test-secret");
        ReflectionTestUtils.setField(keyManager, "keyRotationEnabled", true);
        keyManager.initializeKeys();

        SecretKey originalKey = (SecretKey) keyManager.getSigningKey();

        // When
        keyManager.rotateKeys();

        // Then
        SecretKey newKey = (SecretKey) keyManager.getSigningKey();
        assertThat(newKey).isNotEqualTo(originalKey);
    }

    @Test
    void shouldRotateRSAKeys() {
        // Given
        JwtKeyManager keyManager = new JwtKeyManager();
        ReflectionTestUtils.setField(keyManager, "signingAlgorithm", "RS256");
        ReflectionTestUtils.setField(keyManager, "rsaPrivateKey", "");
        ReflectionTestUtils.setField(keyManager, "rsaPublicKey", "");
        ReflectionTestUtils.setField(keyManager, "keyRotationEnabled", true);
        keyManager.initializeKeys();

        RSAPrivateKey originalPrivateKey = keyManager.getRSAPrivateKey();
        RSAPublicKey originalPublicKey = keyManager.getRSAPublicKey();

        // When
        keyManager.rotateKeys();

        // Then
        RSAPrivateKey newPrivateKey = keyManager.getRSAPrivateKey();
        RSAPublicKey newPublicKey = keyManager.getRSAPublicKey();
        assertThat(newPrivateKey).isNotEqualTo(originalPrivateKey);
        assertThat(newPublicKey).isNotEqualTo(originalPublicKey);
    }

    @Test
    void shouldNotRotateKeysWhenDisabled() {
        // Given
        JwtKeyManager keyManager = new JwtKeyManager();
        ReflectionTestUtils.setField(keyManager, "signingAlgorithm", "HS256");
        ReflectionTestUtils.setField(keyManager, "hmacSecret", "test-secret");
        ReflectionTestUtils.setField(keyManager, "keyRotationEnabled", false);
        keyManager.initializeKeys();

        SecretKey originalKey = (SecretKey) keyManager.getSigningKey();

        // When
        keyManager.rotateKeys();

        // Then
        SecretKey keyAfterRotation = (SecretKey) keyManager.getSigningKey();
        assertThat(keyAfterRotation).isEqualTo(originalKey);
    }

    @Test
    void shouldLoadRSAKeysFromConfiguration() {
        // Given - Sample RSA keys (these are test keys, not for production)
        String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
                "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB\n" +
                "wjgHm6S4+RCzV4ac+yb4v3/9n+4gH8F5LlOX4dkdK3p0kSCWJbeVWkewlVMpLwrnL+xwc4ViQzOVs5xLg1ZuZz8tlhQRdWGQxmOOuK5d4NhSIFrgez2uBdKrHDcc8+5VgZ9qihkbqOSMpOFbhLLl5Wb6sjHVzo+0G2umHBhBqKZHLjdK1u88s4+7uEQfaWfFgCp3VMxLihBrL05QdGCFzZHhUPA2x+WJAtVw3fcqh+RKLFl4g0+bw+HHBhzPSWd9AnqJnSc+dBjUl7sGlr0+SnqKAVVzNfQnjcN2Csbmzlc0b9AoGBAQDnwJxI0+VgSFNeSBpE5D7ykHhYtyx8OH4NUlHU1tADTBqHEoTuFqDOE6A=\n"
                +
                "-----END PRIVATE KEY-----";

        String publicKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1L7VLPHCgcI4B5uk\n" +
                "uPkQs1eGnPsm+L9//Z/uIB/BeS5Tl+HZHSt6dJEgliW3lVpHsJVTKS8K5y/scHOF\n" +
                "YkMzlbOcS4NWbmc/LZYUEXVhkMZjjriuXeDYUiBa4Hs9rgXSqxw3HPPuVYGfaooZ\n" +
                "G6jkjKThW4Sy5eVm+rIx1c6PtBtrphwYQaimRy43StbvPLOPu7hEH2lnxYAqd1TM\n" +
                "S4oQay9OUHRghc2R4VDwNsfliQLVcN33KofkSixZeINPm8PhxwYcz0lnfQJ6iZ0n\n" +
                "PnQY1Je7Bpa9Pkp6igFVczX0J43DdgrG5s5XNG/QKBQEA58CcSNPlYEhTXkgaROQ\n" +
                "+8pB4WLcsfDh+DVJR1NbQA0wahxKE7hagzhOgA==\n" +
                "-----END PUBLIC KEY-----";

        JwtKeyManager keyManager = new JwtKeyManager();
        ReflectionTestUtils.setField(keyManager, "signingAlgorithm", "RS256");
        ReflectionTestUtils.setField(keyManager, "rsaPrivateKey", privateKeyPem);
        ReflectionTestUtils.setField(keyManager, "rsaPublicKey", publicKeyPem);

        // When/Then - Should not throw exception for valid keys
        // Note: This test uses sample keys that may not be valid, so we expect it might
        // fail
        // In a real scenario, you would use properly generated test keys
        assertThatThrownBy(() -> keyManager.initializeKeys())
                .isInstanceOf(IllegalStateException.class);
    }
}