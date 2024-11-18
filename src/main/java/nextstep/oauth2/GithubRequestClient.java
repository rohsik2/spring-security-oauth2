package nextstep.oauth2;

import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class GithubRequestClient {

    private final RestTemplate restTemplate = new RestTemplate();
    private final String GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token";
    public String requestAccessToken(String code) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        Map<String, String> body = new HashMap<>();
        body.put("client_id", "Ov23li2ImAZ1sVvN4hey");
        body.put("client_secret", "02a89e4d8ea5de6f5d8dcd518a6ba2227c571c38");
        body.put("code", code);
        body.put("redirect_uri", "http://localhost:8080/login/oauth2/code/github");

        HttpEntity<Map<String, String>> request = new HttpEntity<>(body, headers);
        ResponseEntity<Map> response = restTemplate.exchange(GITHUB_TOKEN_URL, HttpMethod.POST, request, Map.class);
        return (String) response.getBody().get("access_token");

        //client_id
        //client_secret
        //code
        //redirect_uri

    }
}
