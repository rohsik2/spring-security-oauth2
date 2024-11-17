package nextstep.oauth2.github;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import nextstep.oauth2.OAuth2ProfileUser;

@JsonIgnoreProperties(ignoreUnknown = true)
public class GithubProfileUser implements OAuth2ProfileUser {
    @JsonProperty("id")
    private String id;

    @JsonProperty("name")
    private String name;

    @JsonProperty("avatar_url")
    private String imageUrl;

    @JsonProperty("email")
    private String email;

    @Override
    public String getId() {
        return id;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getImageUrl() {
        return imageUrl;
    }

    @Override
    public String getEmail() {
        return email;
    }
}
