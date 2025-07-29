package com.zamaz.mcp.security.service;

import com.zamaz.mcp.security.audit.SecurityAuditService;
import com.zamaz.mcp.security.entity.OAuth2Client;
import com.zamaz.mcp.security.entity.OAuth2Client.*;
import com.zamaz.mcp.security.exception.ClientRegistrationException;
import com.zamaz.mcp.security.model.OAuth2ClientRegistrationRequest;
import com.zamaz.mcp.security.model.OAuth2ClientUpdateRequest;
import com.zamaz.mcp.security.repository.OAuth2ClientRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for OAuth2ClientService
 */
@ExtendWith(MockitoExtension.class)
class OAuth2ClientServiceTest {

    @Mock
    private OAuth2ClientRepository clientRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private SecurityAuditService auditService;

    @InjectMocks
    private OAuth2ClientService clientService;

    private OAuth2ClientRegistrationRequest registrationRequest;
    private OAuth2Client existingClient;

    @BeforeEach
    void setUp() {
        // Set up registration request
        registrationRequest = OAuth2ClientRegistrationRequest.builder()
            .clientName("Test Client")
            .description("Test client description")
            .clientType(ClientType.CONFIDENTIAL)
            .organizationId("org-123")
            .grantTypes(Set.of(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN))
            .redirectUris(List.of("https://app.example.com/callback"))
            .scopes(Set.of("openid", "profile", "email"))
            .build();

        // Set up existing client
        existingClient = new OAuth2Client();
        existingClient.setId(UUID.randomUUID());
        existingClient.setClientId("mcp_test_client");
        existingClient.setClientName("Existing Test Client");
        existingClient.setClientType(ClientType.CONFIDENTIAL);
        existingClient.setActive(true);
    }

    @Test
    void registerClient_withValidRequest_shouldSucceed() {
        // Given
        when(clientRepository.existsByClientId(anyString())).thenReturn(false);
        when(passwordEncoder.encode(anyString())).thenReturn("encoded-secret");
        when(clientRepository.save(any(OAuth2Client.class))).thenAnswer(invocation -> {
            OAuth2Client client = invocation.getArgument(0);
            client.setId(UUID.randomUUID());
            return client;
        });

        // When
        OAuth2Client result = clientService.registerClient(registrationRequest, "user-123");

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getClientName()).isEqualTo("Test Client");
        assertThat(result.getClientType()).isEqualTo(ClientType.CONFIDENTIAL);
        assertThat(result.getAuthorizedGrantTypes()).containsExactlyInAnyOrder(
            GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN);
        assertThat(result.getAdditionalSettings()).containsKey("_temp_secret");

        verify(clientRepository).save(any(OAuth2Client.class));
        verify(auditService).logClientRegistration(anyString(), eq("user-123"));
    }

    @Test
    void registerClient_withPublicClient_shouldNotGenerateSecret() {
        // Given
        registrationRequest.setClientType(ClientType.PUBLIC);
        when(clientRepository.existsByClientId(anyString())).thenReturn(false);
        when(clientRepository.save(any(OAuth2Client.class))).thenAnswer(invocation -> {
            OAuth2Client client = invocation.getArgument(0);
            client.setId(UUID.randomUUID());
            return client;
        });

        // When
        OAuth2Client result = clientService.registerClient(registrationRequest, "user-123");

        // Then
        assertThat(result.getClientSecret()).isNull();
        assertThat(result.getClientAuthenticationMethods()).containsExactly(ClientAuthenticationMethod.NONE);
        assertThat(result.getRequirePkce()).isTrue();

        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    void registerClient_withInvalidRedirectUri_shouldThrowException() {
        // Given
        registrationRequest.setRedirectUris(List.of("http://insecure.example.com/callback"));

        // When/Then
        assertThatThrownBy(() -> clientService.registerClient(registrationRequest, "user-123"))
            .isInstanceOf(ClientRegistrationException.class)
            .hasMessageContaining("Redirect URIs must use HTTPS");
    }

    @Test
    void registerClient_withDeprecatedGrantType_shouldThrowException() {
        // Given
        registrationRequest.setGrantTypes(Set.of(GrantType.IMPLICIT));

        // When/Then
        assertThatThrownBy(() -> clientService.registerClient(registrationRequest, "user-123"))
            .isInstanceOf(ClientRegistrationException.class)
            .hasMessageContaining("deprecated and not allowed");
    }

    @Test
    void updateClient_withValidRequest_shouldSucceed() {
        // Given
        OAuth2ClientUpdateRequest updateRequest = new OAuth2ClientUpdateRequest();
        updateRequest.setClientName("Updated Client Name");
        updateRequest.setRedirectUris(List.of("https://newapp.example.com/callback"));

        when(clientRepository.findByClientId("mcp_test_client"))
            .thenReturn(Optional.of(existingClient));
        when(clientRepository.save(any(OAuth2Client.class))).thenReturn(existingClient);

        // When
        OAuth2Client result = clientService.updateClient("mcp_test_client", updateRequest, "user-123");

        // Then
        assertThat(result.getClientName()).isEqualTo("Updated Client Name");
        assertThat(result.getRedirectUris()).containsExactly("https://newapp.example.com/callback");

        verify(clientRepository).save(existingClient);
        verify(auditService).logClientUpdate("mcp_test_client", "user-123");
    }

    @Test
    void updateClient_withNonExistentClient_shouldThrowException() {
        // Given
        OAuth2ClientUpdateRequest updateRequest = new OAuth2ClientUpdateRequest();
        when(clientRepository.findByClientId("non-existent")).thenReturn(Optional.empty());

        // When/Then
        assertThatThrownBy(() -> clientService.updateClient("non-existent", updateRequest, "user-123"))
            .isInstanceOf(ClientRegistrationException.class)
            .hasMessageContaining("Client not found");
    }

    @Test
    void regenerateClientSecret_withConfidentialClient_shouldSucceed() {
        // Given
        when(clientRepository.findByClientId("mcp_test_client"))
            .thenReturn(Optional.of(existingClient));
        when(passwordEncoder.encode(anyString())).thenReturn("new-encoded-secret");
        when(clientRepository.save(any(OAuth2Client.class))).thenReturn(existingClient);

        // When
        String newSecret = clientService.regenerateClientSecret("mcp_test_client", "user-123");

        // Then
        assertThat(newSecret).isNotNull();
        assertThat(newSecret).hasSize(48); // Expected secret length

        verify(passwordEncoder).encode(anyString());
        verify(clientRepository).save(existingClient);
        verify(auditService).logClientSecretRegeneration("mcp_test_client", "user-123");
    }

    @Test
    void regenerateClientSecret_withPublicClient_shouldThrowException() {
        // Given
        existingClient.setClientType(ClientType.PUBLIC);
        when(clientRepository.findByClientId("mcp_test_client"))
            .thenReturn(Optional.of(existingClient));

        // When/Then
        assertThatThrownBy(() -> 
            clientService.regenerateClientSecret("mcp_test_client", "user-123"))
            .isInstanceOf(ClientRegistrationException.class)
            .hasMessageContaining("Cannot regenerate secret for public client");
    }

    @Test
    void deactivateClient_shouldSucceed() {
        // Given
        when(clientRepository.findByClientId("mcp_test_client"))
            .thenReturn(Optional.of(existingClient));
        when(clientRepository.save(any(OAuth2Client.class))).thenReturn(existingClient);

        // When
        clientService.deactivateClient("mcp_test_client", "user-123");

        // Then
        assertThat(existingClient.getActive()).isFalse();

        verify(clientRepository).save(existingClient);
        verify(auditService).logClientDeactivation("mcp_test_client", "user-123");
    }

    @Test
    void reactivateClient_shouldSucceed() {
        // Given
        existingClient.setActive(false);
        when(clientRepository.findByClientId("mcp_test_client"))
            .thenReturn(Optional.of(existingClient));
        when(clientRepository.save(any(OAuth2Client.class))).thenReturn(existingClient);

        // When
        clientService.reactivateClient("mcp_test_client", "user-123");

        // Then
        assertThat(existingClient.getActive()).isTrue();

        verify(clientRepository).save(existingClient);
        verify(auditService).logClientReactivation("mcp_test_client", "user-123");
    }

    @Test
    void validateClientCredentials_withValidCredentials_shouldReturnTrue() {
        // Given
        existingClient.setClientSecret("encoded-secret");
        when(clientRepository.findByClientIdAndActiveTrue("mcp_test_client"))
            .thenReturn(Optional.of(existingClient));
        when(passwordEncoder.matches("plain-secret", "encoded-secret")).thenReturn(true);

        // When
        boolean result = clientService.validateClientCredentials("mcp_test_client", "plain-secret");

        // Then
        assertThat(result).isTrue();
    }

    @Test
    void validateClientCredentials_withInvalidCredentials_shouldReturnFalse() {
        // Given
        existingClient.setClientSecret("encoded-secret");
        when(clientRepository.findByClientIdAndActiveTrue("mcp_test_client"))
            .thenReturn(Optional.of(existingClient));
        when(passwordEncoder.matches("wrong-secret", "encoded-secret")).thenReturn(false);

        // When
        boolean result = clientService.validateClientCredentials("mcp_test_client", "wrong-secret");

        // Then
        assertThat(result).isFalse();
    }

    @Test
    void validateClientCredentials_withPublicClient_shouldReturnTrue() {
        // Given
        existingClient.setClientType(ClientType.PUBLIC);
        existingClient.setClientSecret(null);
        when(clientRepository.findByClientIdAndActiveTrue("mcp_test_client"))
            .thenReturn(Optional.of(existingClient));

        // When
        boolean result = clientService.validateClientCredentials("mcp_test_client", null);

        // Then
        assertThat(result).isTrue();
    }

    @Test
    void validateRedirectUri_withExactMatch_shouldReturnTrue() {
        // Given
        existingClient.setRedirectUris(Set.of("https://app.example.com/callback"));
        when(clientRepository.findByClientIdAndActiveTrue("mcp_test_client"))
            .thenReturn(Optional.of(existingClient));

        // When
        boolean result = clientService.validateRedirectUri(
            "mcp_test_client", "https://app.example.com/callback");

        // Then
        assertThat(result).isTrue();
    }

    @Test
    void validateRedirectUri_withLocalhostVariation_shouldReturnTrue() {
        // Given
        existingClient.setRedirectUris(Set.of("http://localhost:3000/callback"));
        when(clientRepository.findByClientIdAndActiveTrue("mcp_test_client"))
            .thenReturn(Optional.of(existingClient));

        // When
        boolean result = clientService.validateRedirectUri(
            "mcp_test_client", "http://127.0.0.1:3000/callback");

        // Then
        assertThat(result).isTrue();
    }

    @Test
    void validateRedirectUri_withMismatch_shouldReturnFalse() {
        // Given
        existingClient.setRedirectUris(Set.of("https://app.example.com/callback"));
        when(clientRepository.findByClientIdAndActiveTrue("mcp_test_client"))
            .thenReturn(Optional.of(existingClient));

        // When
        boolean result = clientService.validateRedirectUri(
            "mcp_test_client", "https://different.example.com/callback");

        // Then
        assertThat(result).isFalse();
    }

    @Test
    void getOrganizationClients_shouldReturnActiveClients() {
        // Given
        List<OAuth2Client> clients = List.of(existingClient);
        when(clientRepository.findByOrganizationIdAndActiveTrue("org-123"))
            .thenReturn(clients);

        // When
        List<OAuth2Client> result = clientService.getOrganizationClients("org-123");

        // Then
        assertThat(result).hasSize(1);
        assertThat(result.get(0)).isEqualTo(existingClient);
    }

    @Test
    void searchClients_shouldReturnMatchingClients() {
        // Given
        List<OAuth2Client> clients = List.of(existingClient);
        when(clientRepository.searchClients("test")).thenReturn(clients);

        // When
        List<OAuth2Client> result = clientService.searchClients("test");

        // Then
        assertThat(result).hasSize(1);
        assertThat(result.get(0)).isEqualTo(existingClient);
    }
}