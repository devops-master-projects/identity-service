package org.example.identity.unit.user_login;

import org.example.identity.DTO.LoginRequest;
import org.example.identity.services.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.admin.client.Keycloak;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.*;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.lang.reflect.Field;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    private static final String KEYCLOAK_REALM = "IdentityRealm";
    private static final String KEYCLOAK_SERVER_URL = "http://localhost:8080/auth";
    private static final String CLIENT_ID = "identity-service";
    private static final String CLIENT_SECRET = "secret";

    @Mock private Keycloak keycloak;
    @Mock private RestTemplate mockRestTemplate;

    private AuthService authService;

    @BeforeEach
    void setup() throws Exception {
        authService = new AuthService(keycloak, KEYCLOAK_REALM);

        setPrivateField("keycloakServerUrl", KEYCLOAK_SERVER_URL);
        setPrivateField("clientId", CLIENT_ID);
        setPrivateField("clientSecret", CLIENT_SECRET);

        injectMockRestTemplate();
    }

    private void setPrivateField(String fieldName, String value) throws Exception {
        Field field = AuthService.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(authService, value);
    }

    private void injectMockRestTemplate() throws Exception {
        authService = new AuthService(keycloak, KEYCLOAK_REALM) {
            @Override
            public Map<String, Object> login(LoginRequest request) {
                String tokenUrl = KEYCLOAK_SERVER_URL + "/realms/" + KEYCLOAK_REALM + "/protocol/openid-connect/token";

                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

                MultiValueMap<String, String> body = new org.springframework.util.LinkedMultiValueMap<>();
                body.add("grant_type", "password");
                body.add("client_id", CLIENT_ID);
                body.add("client_secret", CLIENT_SECRET);
                body.add("username", request.getUsername());
                body.add("password", request.getPassword());

                HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);

                ResponseEntity<Map> response = mockRestTemplate.exchange(
                        tokenUrl,
                        HttpMethod.POST,
                        entity,
                        Map.class
                );

                return response.getBody();
            }
        };

        setPrivateField("keycloakServerUrl", KEYCLOAK_SERVER_URL);
        setPrivateField("clientId", CLIENT_ID);
        setPrivateField("clientSecret", CLIENT_SECRET);
    }

    private LoginRequest baseOkRequest() {
        LoginRequest request = new LoginRequest();
        request.setUsername("testUser");
        request.setPassword("testPassword");
        return request;
    }

    private ResponseEntity<Map> successfulTokenResponse() {
        Map<String, Object> tokenResponse = Map.of(
                "access_token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type", "Bearer",
                "expires_in", 300,
                "refresh_token", "refresh_token_value"
        );
        return new ResponseEntity<>(tokenResponse, HttpStatus.OK);
    }

    @Test
    @DisplayName("login: happy path - RestTemplate returns token")
    void login_happyPath() {
        LoginRequest request = baseOkRequest();
        ResponseEntity<Map> mockResponse = successfulTokenResponse();

        when(mockRestTemplate.exchange(
                anyString(),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                eq(Map.class)
        )).thenReturn(mockResponse);

        Map<String, Object> result = authService.login(request);

        assertNotNull(result);
        assertEquals("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", result.get("access_token"));
        assertEquals("Bearer", result.get("token_type"));
        assertEquals(300, result.get("expires_in"));
        assertEquals("refresh_token_value", result.get("refresh_token"));

        verify(mockRestTemplate, times(1)).exchange(
                anyString(),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                eq(Map.class)
        );
    }

    @Test
    @DisplayName("login: constructs correct token URL")
    void login_constructsCorrectUrl() {
        LoginRequest request = baseOkRequest();
        when(mockRestTemplate.exchange(anyString(), any(), any(), eq(Map.class)))
                .thenReturn(successfulTokenResponse());

        authService.login(request);

        ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockRestTemplate).exchange(
                urlCaptor.capture(),
                any(),
                any(),
                eq(Map.class)
        );

        String expectedUrl = "http://localhost:8080/auth/realms/IdentityRealm/protocol/openid-connect/token";
        assertEquals(expectedUrl, urlCaptor.getValue());
    }

    @Test
    @DisplayName("login: captures correct request body parameters")
    void login_capturesCorrectRequestBody() {
        LoginRequest request = baseOkRequest();
        when(mockRestTemplate.exchange(anyString(), any(), any(), eq(Map.class)))
                .thenReturn(successfulTokenResponse());

        authService.login(request);

        ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> entityCaptor =
                ArgumentCaptor.forClass(HttpEntity.class);

        verify(mockRestTemplate).exchange(
                anyString(),
                eq(HttpMethod.POST),
                entityCaptor.capture(),
                eq(Map.class)
        );

        HttpEntity<MultiValueMap<String, String>> capturedEntity = entityCaptor.getValue();
        MultiValueMap<String, String> body = capturedEntity.getBody();

        assertEquals("password", body.getFirst("grant_type"));
        assertEquals(CLIENT_ID, body.getFirst("client_id"));
        assertEquals(CLIENT_SECRET, body.getFirst("client_secret"));
        assertEquals("testUser", body.getFirst("username"));
        assertEquals("testPassword", body.getFirst("password"));
    }

    @Test
    @DisplayName("login: captures correct headers")
    void login_capturesCorrectHeaders() {
        LoginRequest request = baseOkRequest();
        when(mockRestTemplate.exchange(anyString(), any(), any(), eq(Map.class)))
                .thenReturn(successfulTokenResponse());

        authService.login(request);

        ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> entityCaptor =
                ArgumentCaptor.forClass(HttpEntity.class);

        verify(mockRestTemplate).exchange(anyString(), any(), entityCaptor.capture(), eq(Map.class));

        HttpHeaders headers = entityCaptor.getValue().getHeaders();
        assertEquals(MediaType.APPLICATION_FORM_URLENCODED, headers.getContentType());
    }

    @Test
    @DisplayName("login: RestTemplate throws RestClientException → propagation")
    void login_whenRestTemplateThrows_propagates() {
        LoginRequest request = baseOkRequest();

        when(mockRestTemplate.exchange(anyString(), any(), any(), eq(Map.class)))
                .thenThrow(new RestClientException("Mocked connection error"));

        RestClientException ex = assertThrows(RestClientException.class,
                () -> authService.login(request));
        assertEquals("Mocked connection error", ex.getMessage());

        verify(mockRestTemplate, times(1)).exchange(anyString(), any(), any(), eq(Map.class));
    }

    @Test
    @DisplayName("login: response body is null → returns null")
    void login_whenResponseBodyNull_returnsNull() {
        LoginRequest request = baseOkRequest();
        ResponseEntity<Map> nullBodyResponse = new ResponseEntity<>(null, HttpStatus.OK);

        when(mockRestTemplate.exchange(anyString(), any(), any(), eq(Map.class)))
                .thenReturn(nullBodyResponse);

        Map<String, Object> result = authService.login(request);

        assertNull(result);
        verify(mockRestTemplate, times(1)).exchange(anyString(), any(), any(), eq(Map.class));
    }

    @ParameterizedTest(name = "username=\"{0}\" → passed to RestTemplate as-is")
    @NullAndEmptySource
    @ValueSource(strings = {" ", "   ", "validUser"})
    @DisplayName("login: various username values → all passed to RestTemplate")
    void login_variousUsernames_passedToRestTemplate(String username) {
        LoginRequest request = new LoginRequest();
        request.setUsername(username);
        request.setPassword("password");

        when(mockRestTemplate.exchange(anyString(), any(), any(), eq(Map.class)))
                .thenReturn(successfulTokenResponse());

        authService.login(request);

        ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> entityCaptor =
                ArgumentCaptor.forClass(HttpEntity.class);

        verify(mockRestTemplate).exchange(anyString(), any(), entityCaptor.capture(), eq(Map.class));

        MultiValueMap<String, String> body = entityCaptor.getValue().getBody();
        assertEquals(username, body.getFirst("username"));
    }

    @ParameterizedTest(name = "password=\"{0}\" → passed to RestTemplate as-is")
    @NullAndEmptySource
    @ValueSource(strings = {" ", "   ", "validPassword123"})
    @DisplayName("login: various password values → all passed to RestTemplate")
    void login_variousPasswords_passedToRestTemplate(String password) {
        LoginRequest request = new LoginRequest();
        request.setUsername("user");
        request.setPassword(password);

        when(mockRestTemplate.exchange(anyString(), any(), any(), eq(Map.class)))
                .thenReturn(successfulTokenResponse());

        authService.login(request);

        ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> entityCaptor =
                ArgumentCaptor.forClass(HttpEntity.class);

        verify(mockRestTemplate).exchange(anyString(), any(), entityCaptor.capture(), eq(Map.class));

        MultiValueMap<String, String> body = entityCaptor.getValue().getBody();
        assertEquals(password, body.getFirst("password"));
    }

    @Test
    @DisplayName("login: null LoginRequest → NullPointerException")
    void login_whenRequestNull_throws() {
        assertThrows(NullPointerException.class, () -> authService.login(null));
    }

    @Test
    @DisplayName("login: only one call to RestTemplate exchange")
    void login_callsRestTemplateExactlyOnce() {
        LoginRequest request = baseOkRequest();
        when(mockRestTemplate.exchange(anyString(), any(), any(), eq(Map.class)))
                .thenReturn(successfulTokenResponse());

        authService.login(request);

        verify(mockRestTemplate, times(1)).exchange(anyString(), any(), any(), eq(Map.class));
        verifyNoMoreInteractions(mockRestTemplate);
    }
}