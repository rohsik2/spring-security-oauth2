package nextstep.security.context;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

public class SecurityContextHolderFilter extends GenericFilterBean {
    private final SecurityContextRepository securityContextRepository = new SecurityContextRepository();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws ServletException, IOException {
        SecurityContext context = this.securityContextRepository.loadContext((HttpServletRequest) request);
        try {
            SecurityContextHolder.setContext(context);
            chain.doFilter(request, response);
        } finally {
            SecurityContextHolder.clearContext();
        }
    }
}
