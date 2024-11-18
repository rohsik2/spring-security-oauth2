package nextstep.security.authentication;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nextstep.security.access.RequestMatcher;
import nextstep.security.context.SecurityContext;
import nextstep.security.context.SecurityContextHolder;
import nextstep.security.context.SecurityContextRepository;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

public abstract class AbstractAuthenticationProcessingFilter extends GenericFilterBean {
    private AuthenticationManager authenticationManager;

    private final RequestMatcher requiresAuthenticationRequestMatcher;

    private final SecurityContextRepository securityContextRepository = new SecurityContextRepository();

    private static final AuthenticationSuccessHandler successHandler = (request, response, authentication) -> response.sendRedirect("/");
    private static final AuthenticationFailureHandler failureHandler = (request, response, exception) -> response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());

    protected AbstractAuthenticationProcessingFilter(String filterProcessesUrl, AuthenticationManager authenticationManager) {
        this(request -> {
            String uri = request.getRequestURI();
            return uri.startsWith(filterProcessesUrl);
        }, authenticationManager);
    }

    protected AbstractAuthenticationProcessingFilter(RequestMatcher requiresAuthenticationRequestMatcher, AuthenticationManager authenticationManager) {
        this.requiresAuthenticationRequestMatcher = requiresAuthenticationRequestMatcher;
        this.authenticationManager = authenticationManager;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        if (!requiresAuthentication(request, response)) {
            chain.doFilter(request, response);
            return;
        }

        try {
            Authentication authenticationResult = attemptAuthentication(request, response);
            if (authenticationResult == null) {
                return;
            }
            successfulAuthentication(request, response, authenticationResult);
        } catch (AuthenticationException ex) {
            unsuccessfulAuthentication(request, response, ex);
        }
    }

    private void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authResult) throws ServletException, IOException {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authResult);
        SecurityContextHolder.setContext(context);
        this.securityContextRepository.saveContext(context, request, response);

        this.successHandler.onAuthenticationSuccess(request, response, authResult);
    }

    private void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        SecurityContextHolder.clearContext();

        this.failureHandler.onAuthenticationFailure(request, response, failed);
    }

    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        return this.requiresAuthenticationRequestMatcher.matches(request);
    }

    public abstract Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException;

    protected AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }
}
