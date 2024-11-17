package nextstep.oauth2;

public class OAuth2UserRequest {
    private final String email;
    private final String name;
    private final String imageUrl;

    public OAuth2UserRequest(String email, String name, String imageUrl) {
        this.email = email;
        this.name = name;
        this.imageUrl = imageUrl;
    }

    public String getEmail() {
        return email;
    }

    public String getName() {
        return name;
    }

    public String getImageUrl() {
        return imageUrl;
    }
}
