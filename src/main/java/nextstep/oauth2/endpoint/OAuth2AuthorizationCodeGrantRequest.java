package nextstep.oauth2.endpoint;

import nextstep.oauth2.registration.ClientRegistration;

public class OAuth2AuthorizationCodeGrantRequest {
    private final ClientRegistration clientRegistration;
    private final OAuth2AuthorizationExchange authorizationExchange;

    public OAuth2AuthorizationCodeGrantRequest(ClientRegistration clientRegistration,
                                               OAuth2AuthorizationExchange authorizationExchange) {
        this.clientRegistration = clientRegistration;
        this.authorizationExchange = authorizationExchange;
    }

    public ClientRegistration getClientRegistration() {
        return clientRegistration;
    }

    public OAuth2AuthorizationExchange getAuthorizationExchange() {
        return authorizationExchange;
    }
}
