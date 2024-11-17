package nextstep.oauth2.endpoint;

public class OAuth2AuthorizationExchange {

    private final OAuth2AuthorizationRequest authorizationRequest;
    private final OAuth2AuthorizationResponse authorizationResponse;

    public OAuth2AuthorizationExchange(OAuth2AuthorizationRequest authorizationRequest, OAuth2AuthorizationResponse authorizationResponse) {
        this.authorizationRequest = authorizationRequest;
        this.authorizationResponse = authorizationResponse;
    }

    public OAuth2AuthorizationRequest getAuthorizationRequest() {
        return authorizationRequest;
    }

    public OAuth2AuthorizationResponse getAuthorizationResponse() {
        return authorizationResponse;
    }
}
