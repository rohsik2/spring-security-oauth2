package nextstep.oauth2;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

public class GoogleLoginRedirectFilter extends GenericFilterBean {

    public static final String AUTHORIZATION_REQUEST_URI = "/oauth2/authorization/google";
    public static final String GOOGLE_AUTHORIZATION_URI = "https://accounts.google.com/o/oauth2/auth?";
    public static final String REDIRECT_URI = "http://localhost:8080/login/oauth2/code/google";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        if (!httpRequest.getRequestURI().equals(AUTHORIZATION_REQUEST_URI)) {
            chain.doFilter(request, response);
            return;
        }

        String paramsQuery = UriComponentsBuilder.newInstance()
                .queryParam("client_id", "88951150265-q7aq5urrim4rrtqo62hc96o6r5v7r34c.apps.googleusercontent.com")
                .queryParam("response_type", "code")
                .queryParam("scope", "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email")
                .queryParam("redirect_uri", REDIRECT_URI)
                .build()
                .toUri()
                .getQuery();

        httpResponse.sendRedirect(GOOGLE_AUTHORIZATION_URI + paramsQuery);
    }
}
