package nextstep.oauth2;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Component
@ConfigurationProperties(prefix = "spring.security.oauth2.client")
public class OAuth2ClientProperties {

    private final Map<String, Provider> provider = new HashMap<>();
    private final Map<String, Registration> registration = new HashMap<>();


    public Map<String, Provider> getProvider() {
        return provider;
    }

    public Map<String, Registration> getRegistration() {
        return registration;
    }

    public static class Registration {
        private String provider;
        private String clientId;
        private String clientSecret;
        private String redirectUri;
        private Set<String> scope;

        public String getProvider() {
            return provider;
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

        public Set<String> getScope() {
            return scope;
        }

        public void setProvider(String provider) {
            this.provider = provider;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public void setRedirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
        }

        public void setScope(Set<String> scope) {
            this.scope = scope;
        }
    }

    public static class Provider {
        private String authorizationUri;
        private String tokenUri;
        private String userInfoUri;

        public String getAuthorizationUri() {
            return authorizationUri;
        }

        public String getTokenUri() {
            return tokenUri;
        }

        public String getUserInfoUri() {
            return userInfoUri;
        }

        public void setAuthorizationUri(String authorizationUri) {
            this.authorizationUri = authorizationUri;
        }

        public void setTokenUri(String tokenUri) {
            this.tokenUri = tokenUri;
        }

        public void setUserInfoUri(String userInfoUri) {
            this.userInfoUri = userInfoUri;
        }
    }


}
