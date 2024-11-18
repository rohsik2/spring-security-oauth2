package nextstep.app;

import nextstep.app.domain.Member;
import nextstep.app.infrastructure.InmemoryMemberRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.io.UnsupportedEncodingException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class CsrfTest {
    private static final Member TEST_ADMIN_MEMBER = InmemoryMemberRepository.ADMIN_MEMBER;

    @Autowired
    private MockMvc mockMvc;

    @Test
    public void noToken() throws Exception {
        mockMvc.perform(post("/account/update"))
                .andExpect(status().isForbidden());
    }

    @Test
    public void invalidToken() throws Exception {
        mockMvc.perform(post("/account/update")
                        .header("X-CSRF-TOKEN", "invalid"))
                .andExpect(status().isForbidden());
    }

    @Test
    public void ignoringRequestMatchers() throws Exception {
        MvcResult mvcResult = mockMvc.perform(post("/login")).andReturn();
        assertThat(mvcResult.getResponse().getStatus()).isNotEqualTo(HttpStatus.FORBIDDEN.value());
    }

    @Test
    public void includeToken() throws Exception {
        MvcResult mvcResult = mockMvc.perform(get("/account"))
                .andExpect(status().isOk())
                .andReturn();

        String csrfToken = extractCsrfTokenFromPage(mvcResult);

        assertThat(csrfToken).isNotNull();
    }

    @Test
    public void success() throws Exception {
        MockHttpSession session = new MockHttpSession();

        MvcResult mvcResult = mockMvc.perform(get("/account").session(session))
                .andExpect(status().isOk())
                .andReturn();

        String csrfToken = extractCsrfTokenFromPage(mvcResult);

        mockMvc.perform(post("/account/update")
                        .session(session)
                        .header("X-CSRF-TOKEN", csrfToken)
                        .param("username", "new_username")
                        .param("email", "new_email@example.com")
                        .contentType("application/x-www-form-urlencoded"))
                .andDo(print())
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/account"));
    }

    // HTML 페이지에서 CSRF 토큰을 추출하는 메서드
    private String extractCsrfTokenFromPage(MvcResult mvcResult) throws UnsupportedEncodingException {
        String content = mvcResult.getResponse().getContentAsString();

        // HTML 내 숨겨진 필드로 포함된 CSRF 토큰 추출
        Pattern pattern = Pattern.compile("name=\"_csrf\" value=\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(content);
        if (matcher.find()) {
            return matcher.group(1);
        } else {
            throw new IllegalStateException("CSRF token not found in response");
        }
    }
}