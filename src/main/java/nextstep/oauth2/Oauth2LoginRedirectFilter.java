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

public class Oauth2LoginRedirectFilter extends GenericFilterBean {
    public static final String DEFAULT_AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization/";

    private final OAuth2ClientProperties OAuth2ClientProperties;

    public Oauth2LoginRedirectFilter(nextstep.oauth2.OAuth2ClientProperties oAuth2ClientProperties) {
        OAuth2ClientProperties = oAuth2ClientProperties;
    }

    private String extractRegistrationId(HttpServletRequest request) {
        String uri = request.getRequestURI();

        if (uri.startsWith(DEFAULT_AUTHORIZATION_REQUEST_BASE_URI)) {
            return uri.substring(DEFAULT_AUTHORIZATION_REQUEST_BASE_URI.length());
        }

        return null;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String registrationId = extractRegistrationId(httpRequest);
        if (registrationId == null) {
            chain.doFilter(request, response);
            return;
        }

        OAuth2ClientProperties.Provider provider = OAuth2ClientProperties.getProvider().get(registrationId);
        OAuth2ClientProperties.Registration registration = OAuth2ClientProperties.getRegistration().get(registrationId);

        String paramsQuery = UriComponentsBuilder.newInstance()
                .queryParam("client_id", registration.getClientId())
                .queryParam("response_type", "code")
                .queryParam("scope", registration.getScope())
                .queryParam("redirect_uri", registration.getRedirectUri())
                .build()
                .toUri()
                .getQuery();

        httpResponse.sendRedirect(provider.getAuthorizationUri() + "?" + paramsQuery);
    }
}
