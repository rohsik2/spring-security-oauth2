package nextstep.app.ui;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/account")
public class AccountController {

    @GetMapping
    public String getAccountPage(HttpServletRequest request, Model model) {
        model.addAttribute("username", "username");
        model.addAttribute("email", "username@example.com");

//        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
//        model.addAttribute("csrfToken", csrfToken);

        return "account";
    }

    @PostMapping("/update")
    public String updateAccount(@RequestParam("username") String username, @RequestParam("email") String email) {

        // 사용자 정보를 업데이트하는 로직

        return "redirect:/account";
    }
}