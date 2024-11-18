package nextstep.security.authentication;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public interface AuthenticationFailureHandler {
    void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                 AuthenticationException exception) throws IOException, ServletException;
}
