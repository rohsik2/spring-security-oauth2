package nextstep.security.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;
import java.util.List;

public class FilterChainProxy extends GenericFilterBean {
    private final List<SecurityFilterChain> filterChains;

    public FilterChainProxy(List<SecurityFilterChain> filterChains) {
        this.filterChains = filterChains;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        List<Filter> filters = getFilters((HttpServletRequest) request);

        VirtualFilterChain virtualFilterChain = new VirtualFilterChain(chain, filters);
        virtualFilterChain.doFilter(request, response);
    }

    private List<Filter> getFilters(HttpServletRequest request) {
        for (SecurityFilterChain chain : this.filterChains) {
            if (chain.matches(request)) {
                return chain.getFilters();
            }
        }
        return null;
    }

    private static final class VirtualFilterChain implements FilterChain {

        private final FilterChain originalChain;

        private final List<Filter> additionalFilters;

        private final int size;

        private int currentPosition = 0;

        private VirtualFilterChain(FilterChain chain, List<Filter> additionalFilters) {
            this.originalChain = chain;
            this.additionalFilters = additionalFilters;
            this.size = additionalFilters.size();
        }

        @Override
        public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
            if (this.currentPosition == this.size) {
                this.originalChain.doFilter(request, response);
                return;
            }
            this.currentPosition++;
            Filter nextFilter = this.additionalFilters.get(this.currentPosition - 1);
            nextFilter.doFilter(request, response, this);
        }

    }
}
