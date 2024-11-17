package nextstep.oauth2.authentication;

import nextstep.oauth2.endpoint.*;
import nextstep.security.authentication.Authentication;
import nextstep.security.authentication.AuthenticationException;
import nextstep.security.authentication.AuthenticationProvider;

public class OAuth2AuthorizationCodeAuthenticationProvider implements AuthenticationProvider {
    private final OAuth2AccessTokenResponseClient accessTokenResponseClient = new OAuth2AccessTokenResponseClient();

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication = (OAuth2AuthorizationCodeAuthenticationToken) authentication;
        OAuth2AuthorizationResponse authorizationResponse = authorizationCodeAuthentication.getAuthorizationExchange()
                .getAuthorizationResponse();
        if (authorizationResponse.statusError()) {
            throw new OAuth2AuthorizationException();
        }
        OAuth2AuthorizationRequest authorizationRequest = authorizationCodeAuthentication.getAuthorizationExchange()
                .getAuthorizationRequest();
        if (!authorizationResponse.getState().equals(authorizationRequest.getState())) {
            throw new OAuth2AuthorizationException();
        }
        OAuth2AccessTokenResponse accessTokenResponse = this.accessTokenResponseClient.getTokenResponse(
                new OAuth2AuthorizationCodeGrantRequest(authorizationCodeAuthentication.getClientRegistration(),
                        authorizationCodeAuthentication.getAuthorizationExchange()));

        return new OAuth2AuthorizationCodeAuthenticationToken(
                authorizationCodeAuthentication.getClientRegistration(),
                authorizationCodeAuthentication.getAuthorizationExchange(), accessTokenResponse.getAccessToken());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
