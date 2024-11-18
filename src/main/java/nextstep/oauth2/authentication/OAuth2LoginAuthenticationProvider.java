package nextstep.oauth2.authentication;

import nextstep.oauth2.userinfo.OAuth2User;
import nextstep.oauth2.userinfo.OAuth2UserRequest;
import nextstep.oauth2.userinfo.OAuth2UserService;
import nextstep.security.authentication.Authentication;
import nextstep.security.authentication.AuthenticationException;
import nextstep.security.authentication.AuthenticationProvider;

public class OAuth2LoginAuthenticationProvider implements AuthenticationProvider {

    private final OAuth2AuthorizationCodeAuthenticationProvider authorizationCodeAuthenticationProvider = new OAuth2AuthorizationCodeAuthenticationProvider();

    private final OAuth2UserService userService;

    public OAuth2LoginAuthenticationProvider(OAuth2UserService userService) {
        this.userService = userService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2LoginAuthenticationToken loginAuthenticationToken = (OAuth2LoginAuthenticationToken) authentication;

        OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthenticationToken
                = (OAuth2AuthorizationCodeAuthenticationToken) this.authorizationCodeAuthenticationProvider
                .authenticate(
                        new OAuth2AuthorizationCodeAuthenticationToken(
                                loginAuthenticationToken.getClientRegistration(),
                                loginAuthenticationToken.getAuthorizationExchange()
                        )
                );

        OAuth2AccessToken accessToken = authorizationCodeAuthenticationToken.getAccessToken();
        OAuth2User oauth2User = this.userService.loadUser(new OAuth2UserRequest(
                loginAuthenticationToken.getClientRegistration(), accessToken));

        return new OAuth2LoginAuthenticationToken(
                loginAuthenticationToken.getClientRegistration(), loginAuthenticationToken.getAuthorizationExchange(),
                oauth2User, oauth2User.getAuthorities(), accessToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2LoginAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
