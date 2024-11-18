package nextstep.security.config;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;

import java.util.List;

public interface SecurityFilterChain {

    boolean matches(HttpServletRequest request);

    List<Filter> getFilters();
}
