package nextstep.oauth2.endpoint;

import java.util.Set;

public class OAuth2AuthorizationRequest {

    private String authorizationUri;
    private String clientId;
    private String redirectUri;
    private Set<String> scopes;
    private String state;
    private String authorizationRequestUri;

    public OAuth2AuthorizationRequest(String authorizationUri, String clientId, String redirectUri, Set<String> scopes, String state, String authorizationRequestUri) {
        this.authorizationUri = authorizationUri;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.scopes = scopes;
        this.state = state;
        this.authorizationRequestUri = authorizationRequestUri;
    }

    public String getAuthorizationUri() {
        return authorizationUri;
    }

    public String getClientId() {
        return clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public String getState() {
        return state;
    }

    public String getAuthorizationRequestUri() {
        return authorizationRequestUri;
    }
}
