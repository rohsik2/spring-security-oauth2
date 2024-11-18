package nextstep.oauth2;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

public class GithubLoginRedirectFilter extends GenericFilterBean {


    private static String client_id = "Ov23li2ImAZ1sVvN4hey";
    private static String AUTHORIZATION_REQUEST_URI = "/oauth2/authorization/github";
    private static String GITHUB_AUTHORIZATION_URI = "https://github.com/login/oauth/authorize?response_type=code&client_id=%s&scope=read:user&redirect_uri=http://localhost:8080/login/oauth2/code/github";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        // TODO : 해당 uri가 매칭이 잘 됬는지, 안됬으면 그냥 return;
        if(!httpRequest.getRequestURI().equals(AUTHORIZATION_REQUEST_URI)) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String redirect_uri = String.format(GITHUB_AUTHORIZATION_URI, client_id);
        httpResponse.sendRedirect(redirect_uri);
    }
}
