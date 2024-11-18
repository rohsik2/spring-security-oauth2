package nextstep.oauth2.web;

import jakarta.servlet.http.HttpServletRequest;
import nextstep.oauth2.endpoint.OAuth2AuthorizationRequest;
import nextstep.oauth2.keygen.StateGenerator;
import nextstep.oauth2.registration.ClientRegistration;
import nextstep.oauth2.registration.ClientRegistrationRepository;
import nextstep.security.authentication.AuthenticationException;
import org.springframework.web.util.UriComponentsBuilder;

public class OAuth2AuthorizationRequestResolver {

    private static final StateGenerator DEFAULT_STATE_GENERATOR = new StateGenerator();

    private final String authorizationRequestBaseUri;
    private final ClientRegistrationRepository clientRegistrationRepository;

    public OAuth2AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository, String authorizationRequestBaseUri) {
        this.authorizationRequestBaseUri = authorizationRequestBaseUri;
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        String registrationId = resolveRegistrationId(request);
        if (registrationId == null) {
            return null;
        }
        return resolve(registrationId);
    }

    private String resolveRegistrationId(HttpServletRequest request) {
        String uri = request.getRequestURI();

        if (uri.startsWith(authorizationRequestBaseUri)) {
            return uri.substring(authorizationRequestBaseUri.length());
        }

        return null;
    }

    private OAuth2AuthorizationRequest resolve(String registrationId) {
        ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
        if (clientRegistration == null) {
            throw new AuthenticationException("Invalid Client Registration with Id: " + registrationId);
        }

        String state = DEFAULT_STATE_GENERATOR.generateKey();
        String paramsQuery = UriComponentsBuilder.newInstance()
                .queryParam("client_id", clientRegistration.getClientId())
                .queryParam("response_type", "code")
                .queryParam("scope", clientRegistration.getScopes())
                .queryParam("redirect_uri", clientRegistration.getRedirectUri())
                .queryParam("state", state)
                .build()
                .toUri()
                .getQuery();

        String authorizationRequestUri = clientRegistration.getProviderDetails().getAuthorizationUri() + "?" + paramsQuery;

        return new OAuth2AuthorizationRequest(
                clientRegistration.getProviderDetails().getAuthorizationUri(),
                clientRegistration.getClientId(),
                clientRegistration.getRedirectUri(),
                clientRegistration.getScopes(),
                state,
                authorizationRequestUri
        );
    }
}
