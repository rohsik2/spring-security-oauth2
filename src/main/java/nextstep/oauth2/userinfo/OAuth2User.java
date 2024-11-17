package nextstep.oauth2.userinfo;

import java.util.Map;
import java.util.Set;

public interface OAuth2User {
    Set<String> getAuthorities();

    Map<String, Object> getAttributes();

    String getUserNameAttributeName();
}
