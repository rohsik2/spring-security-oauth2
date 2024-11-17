package nextstep.app.ui;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import nextstep.oauth2.userinfo.OAuth2User;
import nextstep.security.authentication.Authentication;
import nextstep.security.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;


@Controller
public class LoginController {

    @GetMapping("/")
    public String login(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            model.addAttribute("isAuthenticated", true);
            String username = extractUsername(authentication);
            model.addAttribute("userName", username);
        } else {
            model.addAttribute("isAuthenticated", false);
        }
        return "index";
    }

    private String extractUsername(Authentication authentication) {
        if (authentication.getPrincipal() instanceof String) {
            return (String) authentication.getPrincipal();
        }
        if (authentication.getPrincipal() instanceof OAuth2User) {
            String userNameAttributeName = ((OAuth2User) authentication.getPrincipal()).getUserNameAttributeName();
            return (String) ((OAuth2User) authentication.getPrincipal()).getAttributes().get(userNameAttributeName);
        }
        return "";
    }

    @PostMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        Cookie cookie = new Cookie("JSESSIONID", null);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        return "redirect:/";
    }
}