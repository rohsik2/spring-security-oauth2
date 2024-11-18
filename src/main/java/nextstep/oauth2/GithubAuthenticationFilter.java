package nextstep.oauth2;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

public class GithubAuthenticationFilter extends GenericFilterBean {

    private final GithubRequestClient githubRequestClient = new GithubRequestClient();

    private final String GITHUB_CODE_GRANT_URI  = "/login/oauth2/code/github";

    private final String GITHUB_TOKEN_URI = "https://github.com/login/oauth/access_token";


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest)  request;
        HttpServletResponse httpResponse = (HttpServletResponse)  response;

        if(!httpRequest.getRequestURI().equals(GITHUB_CODE_GRANT_URI)) {
            chain.doFilter(request, response);
            return;
        }

        String code = httpRequest.getParameter("code");
        String accessToken = githubRequestClient.requestAccessToken(code);
        System.out.println("accessToken " + accessToken);


    }
}
