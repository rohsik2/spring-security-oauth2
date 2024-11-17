package nextstep.oauth2.userinfo;

import nextstep.oauth2.OAuth2AuthenticationException;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

public class DefaultOAuth2UserService implements OAuth2UserService {

    private static final ParameterizedTypeReference<Map<String, Object>> PARAMETERIZED_RESPONSE_TYPE = new ParameterizedTypeReference<Map<String, Object>>() {
    };

    private final RestTemplate restTemplate = new RestTemplate();

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        Assert.notNull(userRequest, "userRequest cannot be null");
        String userNameAttributeName = getUserNameAttributeName(userRequest);
        RequestEntity<?> request = convertRequestEntity(userRequest);
        ResponseEntity<Map<String, Object>> response = getResponse(request);
        Map<String, Object> attributes = convertAttributes(userRequest, response.getBody());
        return new DefaultOAuth2User(attributes, userNameAttributeName);
    }

    private String getUserNameAttributeName(OAuth2UserRequest userRequest) {
        if (!StringUtils
                .hasText(userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUri())) {
            throw new OAuth2AuthenticationException();
        }
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUserNameAttributeName();

        if (!StringUtils.hasText(userNameAttributeName)) {
            throw new OAuth2AuthenticationException();
        }

        return userNameAttributeName;
    }

    private RequestEntity<?> convertRequestEntity(OAuth2UserRequest userRequest) {
        String userInfoUri = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUri();

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(userRequest.getAccessToken().getTokenValue());

        headers.add(HttpHeaders.ACCEPT, "application/json");

        URI uri = UriComponentsBuilder.fromUriString(userInfoUri).build().toUri();

        return new RequestEntity<>(headers, HttpMethod.GET, uri);
    }

    private Map<String, Object> convertAttributes(OAuth2UserRequest userRequest, Map<String, Object> body) {
        // Example transformation logic
        Map<String, Object> convertedAttributes = new HashMap<>(body);

        // Add a custom attribute based on the client registration ID
        String clientRegistrationId = userRequest.getClientRegistration().getRegistrationId();
        convertedAttributes.put("custom_attribute", "value_based_on_" + clientRegistrationId);

        // Modify or add other attributes if needed
        if (convertedAttributes.containsKey("name")) {
            String originalName = (String) convertedAttributes.get("name");
            convertedAttributes.put("name", originalName.toUpperCase()); // Example modification
        }

        return convertedAttributes;
    }

    private ResponseEntity<Map<String, Object>> getResponse(RequestEntity<?> request) {
        try {
            return this.restTemplate.exchange(request, PARAMETERIZED_RESPONSE_TYPE);
        } catch (Exception e) {
            throw new OAuth2AuthenticationException();
        }
    }
}
