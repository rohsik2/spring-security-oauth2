package nextstep.oauth2.endpoint;

public class OAuth2AuthorizationResponse {
    private String code;
    private String redirectUri;
    private String state;

    public OAuth2AuthorizationResponse(String code, String redirectUri, String state) {
        this.code = code;
        this.redirectUri = redirectUri;
        this.state = state;
    }

    public static OAuth2AuthorizationResponse success(String code, String redirectUri, String state) {
        return new OAuth2AuthorizationResponse(code, redirectUri, state);
    }

    public static OAuth2AuthorizationResponse error(String code, String redirectUri, String state) {
        return null;
    }

    public String getCode() {
        return code;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getState() {
        return state;
    }

    public boolean statusError() {
        return false;
    }
}
