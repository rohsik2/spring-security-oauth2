package nextstep.oauth2.userinfo;

import java.util.Map;
import java.util.Set;

public class DefaultOAuth2User implements OAuth2User {

    private final Map<String, Object> attributes;
    private final String userNameAttributeName;

    public DefaultOAuth2User(Map<String, Object> attributes, String userNameAttributeName) {
        this.attributes = attributes;
        this.userNameAttributeName = userNameAttributeName;
    }

    @Override
    public Set<String> getAuthorities() {
        return Set.of();
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getUserNameAttributeName() {
        return userNameAttributeName;
    }
}
