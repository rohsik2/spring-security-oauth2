package nextstep.oauth2.registration;

import java.io.Serializable;
import java.util.Collections;
import java.util.Set;

public class ClientRegistration {

    private String registrationId;

    private String clientId;

    private String clientSecret;

//    private ClientAuthenticationMethod clientAuthenticationMethod;

//    private AuthorizationGrantType authorizationGrantType;

    private String redirectUri;

    private Set<String> scopes = Collections.emptySet();

    private ProviderDetails providerDetails;


    public ClientRegistration(String registrationId, String clientId, String clientSecret, String redirectUri, Set<String> scopes, String authorizationUri, String tokenUri, String uri, String userNameAttributeName) {
        this.registrationId = registrationId;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
        this.scopes = scopes;
        this.providerDetails = new ProviderDetails(authorizationUri, tokenUri, uri, userNameAttributeName);
    }

    public String getRegistrationId() {
        return registrationId;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public ProviderDetails getProviderDetails() {
        return providerDetails;
    }

    public class ProviderDetails implements Serializable {

        private String authorizationUri;

        private String tokenUri;

        private UserInfoEndpoint userInfoEndpoint;

        public ProviderDetails(String authorizationUri, String tokenUri, String uri, String userNameAttributeName) {
            this.authorizationUri = authorizationUri;
            this.tokenUri = tokenUri;
            this.userInfoEndpoint = new UserInfoEndpoint(uri, userNameAttributeName);
        }

        public String getAuthorizationUri() {
            return authorizationUri;
        }

        public String getTokenUri() {
            return tokenUri;
        }

        public UserInfoEndpoint getUserInfoEndpoint() {
            return userInfoEndpoint;
        }

        public class UserInfoEndpoint implements Serializable {

            private String uri;

            private String userNameAttributeName;

            public UserInfoEndpoint(String uri, String userNameAttributeName) {
                this.uri = uri;
                this.userNameAttributeName = userNameAttributeName;
            }

            public String getUri() {
                return uri;
            }

            public String getUserNameAttributeName() {
                return userNameAttributeName;
            }
        }
    }
}
