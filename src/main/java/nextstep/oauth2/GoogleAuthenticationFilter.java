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
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

public class GoogleAuthenticationFilter extends GenericFilterBean {
    private final GoogleRequestClient googleRequestClient = new GoogleRequestClient();
    private MemberRepository memberRepository = new InmemoryMemberRepository();
    private final HttpSessionSecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        if (!httpRequest.getRequestURI().startsWith("/login/oauth2/code/google")) {
            chain.doFilter(request, response);
            return;
        }

        try {
            String code = httpRequest.getParameter("code");
            String accessToken = googleRequestClient.requestAccessToken(code);
            Map<String, String> userProfile = googleRequestClient.requestUserProfile(accessToken);

            Member member = memberRepository.findByEmail(userProfile.get("email"))
                    .orElse(memberRepository.save(new Member(userProfile.get("email"), "", userProfile.get("name"), userProfile.get("picture"), Set.of("USER"))));

            Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(member.getEmail(), null, member.getRoles());

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
            this.securityContextRepository.saveContext(context, httpRequest, httpResponse);

            httpResponse.setStatus(HttpServletResponse.SC_FOUND);
            httpResponse.addHeader("Location", "/");

        } catch (Exception e) {
            httpResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            httpResponse.getWriter().write("{\"error\": \"Failed to authenticate with Oauth2\"}");
        }
    }
}
