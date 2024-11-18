package nextstep.oauth2;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nextstep.app.domain.Member;
import nextstep.app.domain.MemberRepository;
import nextstep.app.infrastructure.InmemoryMemberRepository;
import nextstep.security.authentication.Authentication;
import nextstep.security.authentication.UsernamePasswordAuthenticationToken;
import nextstep.security.context.HttpSessionSecurityContextRepository;
import nextstep.security.context.SecurityContext;
import nextstep.security.context.SecurityContextHolder;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class GithubAuthenticationFilter extends GenericFilterBean {


    private final GithubRequestClient githubRequestClient = new GithubRequestClient();
    private final MemberRepository memberRepository = new InmemoryMemberRepository();

    private final HttpSessionSecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    private final String GITHUB_CODE_GRANT_URI = "/login/oauth2/code/github";

    private final String GITHUB_TOKEN_URI = "https://github.com/login/oauth/access_token";


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        if (!httpRequest.getRequestURI().equals(GITHUB_CODE_GRANT_URI)) {
            chain.doFilter(request, response);
            return;
        }

        try {
            String code = httpRequest.getParameter("code");
            String accessToken = githubRequestClient.requestAccessToken(code);
            Map<String, String> userProfile = githubRequestClient.requestUserProfile(accessToken);

            Member member = memberRepository.findByEmail(userProfile.get("email")).orElse(
                    memberRepository.save(
                            new Member(userProfile.get("email"), "", userProfile.get("name"), userProfile.get("avatar_url"), Set.of("USER"))
                    )
            );

            Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
                    member.getEmail(), null, member.getRoles()
            );

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);

            securityContextRepository.saveContext(context, httpRequest, httpResponse);

            httpResponse.sendRedirect("/");
        } catch (Exception e) {
            httpResponse.sendError(HttpStatus.BAD_REQUEST.value(), "{ \"error\" : \"Failed to authenticate with GitHub\"}");
        }

    }
}
