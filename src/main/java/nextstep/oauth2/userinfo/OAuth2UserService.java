package nextstep.oauth2.userinfo;

public interface OAuth2UserService {
    OAuth2User loadUser(OAuth2UserRequest userRequest);
}
