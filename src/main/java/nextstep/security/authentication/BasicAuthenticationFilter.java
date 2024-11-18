package nextstep.security.authentication;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nextstep.security.context.SecurityContext;
import nextstep.security.context.SecurityContextHolder;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class BasicAuthenticationFilter extends OncePerRequestFilter {
    public static final String AUTHENTICATION_SCHEME_BASIC = "Basic";

    private final AuthenticationManager authenticationManager;

    public BasicAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            Authentication authRequest = convert(request);
            if (authRequest == null) {
                filterChain.doFilter(request, response);
                return;
            }
            String username = authRequest.getPrincipal().toString();

            if (authenticationIsRequired(username)) {
                Authentication authResult = this.authenticationManager.authenticate(authRequest);
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(authResult);
                SecurityContextHolder.setContext(context);
            }

        } catch (AuthenticationException e) {
            response.setHeader("WWW-Authenticate", "Basic realm=\"realmName\"");
            response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
            return;
        }

        filterChain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken convert(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null) {
            return null;
        }
        header = header.trim();
        if (!StringUtils.startsWithIgnoreCase(header, AUTHENTICATION_SCHEME_BASIC)) {
            return null;
        }
        if (header.equalsIgnoreCase(AUTHENTICATION_SCHEME_BASIC)) {
            throw new AuthenticationException();
        }
        byte[] base64Token = header.substring(6).getBytes(StandardCharsets.UTF_8);
        byte[] decoded = decode(base64Token);
        String token = new String(decoded, StandardCharsets.UTF_8);
        int delim = token.indexOf(":");
        if (delim == -1) {
            throw new AuthenticationException();
        }

        return UsernamePasswordAuthenticationToken
                .unauthenticated(token.substring(0, delim), token.substring(delim + 1));
    }

    private byte[] decode(byte[] base64Token) {
        try {
            return Base64.getDecoder().decode(base64Token);
        } catch (IllegalArgumentException ex) {
            throw new AuthenticationException();
        }
    }

    private boolean authenticationIsRequired(String username) {
        Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
        return existingAuth == null || !existingAuth.getPrincipal().equals(username) || !existingAuth.isAuthenticated();
    }
}
