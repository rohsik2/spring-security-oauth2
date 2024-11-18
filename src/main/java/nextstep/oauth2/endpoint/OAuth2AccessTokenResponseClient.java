package nextstep.oauth2.endpoint;

import nextstep.oauth2.authentication.OAuth2AccessToken;
import nextstep.oauth2.authentication.OAuth2AuthorizationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Map;

public class OAuth2AccessTokenResponseClient {

    private final RestTemplate restOperations = new RestTemplate();

    public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest) {

        RequestEntity<?> request = convertRequestEntity(authorizationCodeGrantRequest);
        OAuth2AccessTokenResponse tokenResponse = getResponse(request);
        Assert.notNull(tokenResponse,
                "The authorization server responded to this Authorization Code grant request with an empty body; as such, it cannot be materialized into an OAuth2AccessTokenResponse instance. Please check the HTTP response code in your server logs for more details.");
        return tokenResponse;
    }

    private RequestEntity<?> convertRequestEntity(OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest) {
        // Extract data from authorizationCodeGrantRequest
        String tokenUri = authorizationCodeGrantRequest.getClientRegistration().getProviderDetails().getTokenUri();
        String clientId = authorizationCodeGrantRequest.getClientRegistration().getClientId();
        String clientSecret = authorizationCodeGrantRequest.getClientRegistration().getClientSecret();
        String redirectUri = authorizationCodeGrantRequest.getAuthorizationExchange().getAuthorizationRequest().getRedirectUri();
        String authorizationCode = authorizationCodeGrantRequest.getAuthorizationExchange().getAuthorizationResponse().getCode();
        String state = authorizationCodeGrantRequest.getAuthorizationExchange().getAuthorizationRequest().getState();

        // Create request body
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("code", authorizationCode);
        body.add("redirect_uri", redirectUri);
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("state", state);

        // Create headers
        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type", "application/x-www-form-urlencoded");

        // Create URI
        URI uri = UriComponentsBuilder.fromUriString(tokenUri).build().toUri();

        // Build the RequestEntity
        return new RequestEntity<>(body, headers, HttpMethod.POST, uri);
    }


    private OAuth2AccessTokenResponse getResponse(RequestEntity<?> request) {
        try {
            ResponseEntity<Map> results = this.restOperations.exchange(request, Map.class);
            String accessToken = (String) results.getBody().get("access_token");
            return new OAuth2AccessTokenResponse(new OAuth2AccessToken(accessToken));
        } catch (Exception e) {
            throw new OAuth2AuthorizationException();
        }
    }
}

