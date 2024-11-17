package nextstep.oauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class OAuth2RequestClient {
    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public String requestAccessToken(String code, OAuth2ClientProperties.Provider provider, OAuth2ClientProperties.Registration registration) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        Map<String, String> body = new HashMap<>();
        body.put("client_id", registration.getClientId());
        body.put("client_secret", registration.getClientSecret());
        body.put("code", code);
        body.put("redirect_uri", registration.getRedirectUri());
        body.put("grant_type", "authorization_code");

        HttpEntity<Map<String, String>> request = new HttpEntity<>(body, headers);
        ResponseEntity<Map> response = restTemplate.exchange(provider.getTokenUri(), HttpMethod.POST, request, Map.class);
        return (String) response.getBody().get("access_token");
    }

    public OAuth2ProfileUser requestUserProfile(String accessToken, OAuth2ClientProperties.Provider provider, Class<? extends OAuth2ProfileUser> targetType) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                provider.getUserInfoUri(),
                HttpMethod.GET,
                requestEntity,
                Map.class
        );

        return objectMapper.convertValue(response.getBody(), targetType);
    }
}