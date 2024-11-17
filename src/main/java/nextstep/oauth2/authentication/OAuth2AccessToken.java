package nextstep.oauth2.authentication;

public class OAuth2AccessToken {

    private final String tokenValue;

    public OAuth2AccessToken(String tokenValue) {
        this.tokenValue = tokenValue;
    }

    public String getTokenValue() {
        return tokenValue;
    }
}
