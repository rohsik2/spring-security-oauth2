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
import java.util.Map;

public class OAuth2LoginRedirectFilter extends GenericFilterBean {
    private final OAuth2ClientProperties oAuth2ClientProperties;

    private static final String AUTHORIZATION_REQUEST_URI = "/oauth2/authorization/";

    public OAuth2LoginRedirectFilter(OAuth2ClientProperties oAuth2ClientProperties) {
        super();
        this.oAuth2ClientProperties = oAuth2ClientProperties;
    }

    private String extractRegistrationId(HttpServletRequest request){
        if(request.getRequestURI().startsWith(AUTHORIZATION_REQUEST_URI)){
            return request.getRequestURI().substring(AUTHORIZATION_REQUEST_URI.length());
        }
        return null;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        if (!httpRequest.getRequestURI().startsWith(AUTHORIZATION_REQUEST_URI)) {
            chain.doFilter(request, response);
            return;
        }

        String registrationId = extractRegistrationId(httpRequest);
        OAuth2ClientProperties.Provider provider = oAuth2ClientProperties.getProvider().get(registrationId);
        OAuth2ClientProperties.Registration registration = oAuth2ClientProperties.getRegistration().get(registrationId);

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
