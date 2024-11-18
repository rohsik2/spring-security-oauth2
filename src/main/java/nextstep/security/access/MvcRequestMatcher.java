package nextstep.security.access;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpMethod;

public class MvcRequestMatcher implements RequestMatcher {

    private HttpMethod method;
    private String pattern;

    public MvcRequestMatcher(HttpMethod method, String pattern) {
        this.method = method;
        this.pattern = pattern;
    }

    public HttpMethod getMethod() {
        return method;
    }

    public String getPattern() {
        return pattern;
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        if (notMatchMethod(request)) {
            return false;
        }

        return request.getRequestURI().equals(pattern);
    }

    private boolean notMatchMethod(HttpServletRequest request) {
        return this.method != null && !this.method.name().equals(request.getMethod());
    }
}
