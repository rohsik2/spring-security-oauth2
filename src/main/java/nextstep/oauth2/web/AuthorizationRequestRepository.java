package nextstep.oauth2.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import nextstep.oauth2.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.Assert;

public class AuthorizationRequestRepository {

    private static final String DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME = AuthorizationRequestRepository.class
            .getName() + ".AUTHORIZATION_REQUEST";

    private final String sessionAttributeName = DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME;

    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        Assert.notNull(request, "request cannot be null");
        String stateParameter = getStateParameter(request);
        if (stateParameter == null) {
            return null;
        }
        OAuth2AuthorizationRequest authorizationRequest = getAuthorizationRequest(request);
        return (authorizationRequest != null && stateParameter.equals(authorizationRequest.getState()))
                ? authorizationRequest : null;
    }

    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request,
                                         HttpServletResponse response) {
        Assert.notNull(request, "request cannot be null");
        Assert.notNull(response, "response cannot be null");
        if (authorizationRequest == null) {
            removeAuthorizationRequest(request, response);
            return;
        }
        String state = authorizationRequest.getState();
        Assert.hasText(state, "authorizationRequest.state cannot be empty");
        request.getSession().setAttribute(this.sessionAttributeName, authorizationRequest);
    }

    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request,
                                                                 HttpServletResponse response) {
        Assert.notNull(response, "response cannot be null");
        OAuth2AuthorizationRequest authorizationRequest = loadAuthorizationRequest(request);
        if (authorizationRequest != null) {
            request.getSession().removeAttribute(this.sessionAttributeName);
        }
        return authorizationRequest;
    }

    private String getStateParameter(HttpServletRequest request) {
        return request.getParameter(OAuth2ParameterNames.STATE);
    }

    private OAuth2AuthorizationRequest getAuthorizationRequest(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return (session != null) ? (OAuth2AuthorizationRequest) session.getAttribute(this.sessionAttributeName) : null;
    }
}
