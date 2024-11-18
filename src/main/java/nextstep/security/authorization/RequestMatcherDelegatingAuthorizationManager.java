package nextstep.security.authorization;

import jakarta.servlet.http.HttpServletRequest;
import nextstep.security.access.RequestMatcher;
import nextstep.security.access.RequestMatcherEntry;
import nextstep.security.authentication.Authentication;

import java.util.List;

public class RequestMatcherDelegatingAuthorizationManager implements AuthorizationManager<HttpServletRequest> {
    private final List<RequestMatcherEntry<AuthorizationManager>> mappings;

    public RequestMatcherDelegatingAuthorizationManager(List<RequestMatcherEntry<AuthorizationManager>> mappings) {
        this.mappings = mappings;
    }

    @Override
    public AuthorizationDecision check(Authentication authentication, HttpServletRequest request) {
        for (RequestMatcherEntry<AuthorizationManager> mapping : mappings) {
            RequestMatcher matcher = mapping.getRequestMatcher();
            if (matcher.matches(request)) {
                AuthorizationManager manager = mapping.getEntry();

                return manager.check(authentication, request);
            }
        }

        return new AuthorizationDecision(true);
    }
}
