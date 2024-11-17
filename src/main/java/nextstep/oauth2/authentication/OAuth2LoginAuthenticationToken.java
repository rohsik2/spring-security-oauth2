package nextstep.oauth2.authentication;

import nextstep.oauth2.endpoint.OAuth2AuthorizationExchange;
import nextstep.oauth2.registration.ClientRegistration;
import nextstep.oauth2.userinfo.OAuth2User;
import nextstep.security.authentication.Authentication;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.Set;

public class OAuth2LoginAuthenticationToken implements Authentication {

    private OAuth2User principal;

    private ClientRegistration clientRegistration;

    private OAuth2AuthorizationExchange authorizationExchange;

    private OAuth2AccessToken accessToken;

    private Set<String> authorities;

    private boolean authenticated;

    public OAuth2LoginAuthenticationToken(ClientRegistration clientRegistration,
                                          OAuth2AuthorizationExchange authorizationExchange) {
        this.authorities = Collections.emptySet();
        Assert.notNull(clientRegistration, "clientRegistration cannot be null");
        Assert.notNull(authorizationExchange, "authorizationExchange cannot be null");
        this.clientRegistration = clientRegistration;
        this.authorizationExchange = authorizationExchange;
        this.authenticated = false;
    }

    public OAuth2LoginAuthenticationToken(ClientRegistration clientRegistration,
                                          OAuth2AuthorizationExchange authorizationExchange, OAuth2User principal,
                                          Set<String> authorities, OAuth2AccessToken accessToken) {
        this.authorities = authorities;
        Assert.notNull(clientRegistration, "clientRegistration cannot be null");
        Assert.notNull(authorizationExchange, "authorizationExchange cannot be null");
        Assert.notNull(principal, "principal cannot be null");
        Assert.notNull(accessToken, "accessToken cannot be null");
        this.clientRegistration = clientRegistration;
        this.authorizationExchange = authorizationExchange;
        this.principal = principal;
        this.accessToken = accessToken;
        this.authenticated = true;
    }

    @Override
    public Set<String> getAuthorities() {
        return authorities;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public OAuth2User getPrincipal() {
        return principal;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    public ClientRegistration getClientRegistration() {
        return clientRegistration;
    }

    public OAuth2AuthorizationExchange getAuthorizationExchange() {
        return authorizationExchange;
    }

    public OAuth2AccessToken getAccessToken() {
        return accessToken;
    }
}
