package nextstep.oauth2;

import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class GoogleRequestClient {
//    private static final String GOOGLE_TOKEN_URL = "https://accounts.google.com/o/oauth2/token";
//    public static final String GOOGLE_PROFILE_URL = "https://www.googleapis.com/oauth2/v1/userinfo";
    private static final String GOOGLE_TOKEN_URL = "http://localhost:8089/o/oauth2/token";
    public static final String GOOGLE_PROFILE_URL = "http://localhost:8089/oauth2/v1/userinfo";
    private final RestTemplate restTemplate = new RestTemplate();

    public String requestAccessToken(String code) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        Map<String, String> body = new HashMap<>();
        body.put("client_id", "88951150265-q7aq5urrim4rrtqo62hc96o6r5v7r34c.apps.googleusercontent.com");
        body.put("client_secret", "your_client_secret"); // TODO: client_secret을 작성해주세요.
        body.put("code", code);
        body.put("redirect_uri", GoogleLoginRedirectFilter.REDIRECT_URI);
        body.put("grant_type", "authorization_code");

        HttpEntity<Map<String, String>> request = new HttpEntity<>(body, headers);
        ResponseEntity<Map> response = restTemplate.exchange(GOOGLE_TOKEN_URL, HttpMethod.POST, request, Map.class);
        return (String) response.getBody().get("access_token");
    }

    public Map<String, String> requestUserProfile(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<Void> request = new HttpEntity<>(headers);
        ResponseEntity<Map> response = restTemplate.exchange(GOOGLE_PROFILE_URL, HttpMethod.GET, request, Map.class);
        return response.getBody();
    }
}
