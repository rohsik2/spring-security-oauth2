package nextstep.oauth2;

import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class GithubRequestClient {
    private static final String GITHUB_TOKEN_URL = "http://localhost:8089/login/oauth/access_token";
    public static final String GITHUB_PROFILE_URL = "http://localhost:8089/user";
    private final RestTemplate restTemplate = new RestTemplate();

    public String requestAccessToken(String code) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        Map<String, String> body = new HashMap<>();
        body.put("client_id", "Ov23liTBhugSIcf8VX1v");
        body.put("client_secret", "your_client_secret");
        body.put("code", code);
        body.put("redirect_uri", GithubLoginRedirectFilter.REDIRECT_URI);

        HttpEntity<Map<String, String>> request = new HttpEntity<>(body, headers);
        ResponseEntity<Map> response = restTemplate.exchange(GITHUB_TOKEN_URL, HttpMethod.POST, request, Map.class);
        return (String) response.getBody().get("access_token");
    }

    public Map<String, String> requestUserProfile(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<Void> request = new HttpEntity<>(headers);
        ResponseEntity<Map> response = restTemplate.exchange(GITHUB_PROFILE_URL, HttpMethod.GET, request, Map.class);
        return response.getBody();
    }
}
