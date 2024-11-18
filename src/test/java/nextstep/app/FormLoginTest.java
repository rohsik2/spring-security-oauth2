package nextstep.app;

import nextstep.app.domain.Member;
import nextstep.app.infrastructure.InmemoryMemberRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class FormLoginTest {
    private static final Member TEST_ADMIN_MEMBER = InmemoryMemberRepository.ADMIN_MEMBER;
    private static final Member TEST_USER_MEMBER = InmemoryMemberRepository.USER_MEMBER;

    @Autowired
    private MockMvc mockMvc;

    @DisplayName("로그인 성공")
    @Test
    void login_success() throws Exception {
        ResultActions loginResponse = mockMvc.perform(post("/login")
                .param("username", TEST_USER_MEMBER.getEmail())
                .param("password", TEST_USER_MEMBER.getPassword())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        );

        loginResponse.andExpect(status().is3xxRedirection());
    }

    @DisplayName("로그인 실패 - 사용자 없음")
    @Test
    void login_fail_with_no_user() throws Exception {
        ResultActions response = mockMvc.perform(post("/login")
                .param("username", "none")
                .param("password", "none")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        );

        response.andExpect(status().isUnauthorized());
    }

    @DisplayName("로그인 실패 - 비밀번호 불일치")
    @Test
    void login_fail_with_invalid_password() throws Exception {
        ResultActions response = mockMvc.perform(post("/login")
                .param("username", TEST_USER_MEMBER.getEmail())
                .param("password", "invalid")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        );

        response.andExpect(status().isUnauthorized());
    }

    @DisplayName("로그인 후 세션을 통해 회원 목록 조회")
    @Test
    void admin_login_after_members() throws Exception {
        MockHttpSession session = new MockHttpSession();

        ResultActions loginResponse = mockMvc.perform(post("/login")
                .param("username", TEST_ADMIN_MEMBER.getEmail())
                .param("password", TEST_ADMIN_MEMBER.getPassword())
                .session(session)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        );

        loginResponse.andExpect(status().is3xxRedirection());

        ResultActions membersResponse = mockMvc.perform(get("/members")
                .session(session)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        );

        membersResponse.andExpect(status().isOk());
    }

    @DisplayName("일반 회원은 회원 목록 조회 불가능")
    @Test
    void user_login_after_members() throws Exception {
        MockHttpSession session = new MockHttpSession();

        ResultActions loginResponse = mockMvc.perform(post("/login")
                .param("username", TEST_USER_MEMBER.getEmail())
                .param("password", TEST_USER_MEMBER.getPassword())
                .session(session)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        );

        loginResponse.andExpect(status().is3xxRedirection());

        ResultActions membersResponse = mockMvc.perform(get("/members")
                .session(session)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        );

        membersResponse.andExpect(status().isForbidden());
    }
}
