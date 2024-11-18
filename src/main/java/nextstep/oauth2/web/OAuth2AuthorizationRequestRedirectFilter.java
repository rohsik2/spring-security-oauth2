package nextstep.oauth2.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nextstep.oauth2.endpoint.OAuth2AuthorizationRequest;
import nextstep.oauth2.registration.ClientRegistrationRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class OAuth2AuthorizationRequestRedirectFilter extends OncePerRequestFilter {

    public static final String DEFAULT_AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization/";

    private final OAuth2AuthorizationRequestResolver authorizationRequestResolver;

    private final AuthorizationRequestRepository authorizationRequestRepository = new AuthorizationRequestRepository();

    public OAuth2AuthorizationRequestRedirectFilter(ClientRegistrationRepository clientRegistrationRepository) {
        authorizationRequestResolver = new OAuth2AuthorizationRequestResolver(clientRegistrationRepository, DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestResolver.resolve(request);
        if (authorizationRequest != null) {
            sendRedirectForAuthorization(request, response, authorizationRequest);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void sendRedirectForAuthorization(HttpServletRequest request, HttpServletResponse response,
                                              OAuth2AuthorizationRequest authorizationRequest) throws IOException {
        this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response);
        response.sendRedirect(authorizationRequest.getAuthorizationRequestUri());
    }
}
