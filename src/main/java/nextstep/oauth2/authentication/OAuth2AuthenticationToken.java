package nextstep.oauth2.authentication;

import nextstep.oauth2.userinfo.OAuth2User;
import nextstep.security.authentication.Authentication;
import org.springframework.util.Assert;

import java.util.Set;

public class OAuth2AuthenticationToken implements Authentication {
    private final OAuth2User principal;

    private final Set<String> authorities;

    private final boolean authenticated;

    public OAuth2AuthenticationToken(OAuth2User principal, Set<String> authorities, boolean authenticated) {
        this.principal = principal;
        this.authorities = authorities;
        this.authenticated = authenticated;
    }

    public OAuth2AuthenticationToken(OAuth2User principal, Set<String> authorities) {
        this.authorities = authorities;
        Assert.notNull(principal, "principal cannot be null");
        this.principal = principal;
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
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    public String getName() {
        return principal.toString();
    }
}
