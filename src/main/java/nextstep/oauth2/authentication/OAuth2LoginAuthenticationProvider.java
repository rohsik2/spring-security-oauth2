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

//    private Class<? extends OAuth2ProfileUser> findProfileUserType(nextstep.oauth2.OAuth2ClientProperties.Registration registration) {
//        if (Objects.equals(registration.getProvider(), "github")) {
//            return GithubProfileUser.class;
//        }
//        if (Objects.equals(registration.getProvider(), "google")) {
//            return GoogleProfileUser.class;
//        }
//
//        throw new IllegalArgumentException("지원하지 않는 OAuth2 Provider 입니다.");
//    }

//    private String requestAccessToken(String code, OAuth2ClientProperties.Provider provider, OAuth2ClientProperties.Registration registration) {
//        String uri = UriComponentsBuilder.newInstance()
//                .queryParam("client_id", registration.getClientId())
//                .queryParam("client_secret", registration.getClientSecret())
//                .queryParam("code", code)
//                .queryParam("grant_type", "authorization_code")
//                .queryParam("redirect_uri", registration.getRedirectUri())
//                .build()
//                .toUriString();
//
//        HttpHeaders headers = new HttpHeaders();
//        headers.add("Accept", "application/json"); // JSON 형식의 응답을 받기 위해 헤더 추가
//
//        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
//
//        try {
//            ResponseEntity<Map> response = restTemplate.exchange(
//                    provider.getTokenUri() + uri,
//                    HttpMethod.POST,
//                    requestEntity,
//                    Map.class
//            );
//
//            Map<String, String> body = response.getBody();
//            if (body != null && body.containsKey("access_token")) {
//                return body.get("access_token");
//            }
//
//            return null;
//        } catch (Exception e) {
//            throw new RuntimeException();
//        }
//    }
//
//    public OAuth2ProfileUser requestProfile(String accessToken, OAuth2ClientProperties.Provider provider, Class<? extends OAuth2ProfileUser> targetType) {
//        HttpHeaders headers = new HttpHeaders();
//        headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken); // Bearer 토큰을 사용한 인증
//
//        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
//
//        ResponseEntity<Map> response = restTemplate.exchange(
//                provider.getUserInfoUri(),
//                HttpMethod.GET,
//                requestEntity,
//                Map.class
//        );
//
//        return objectMapper.convertValue(response.getBody(), targetType);
//    }
}
