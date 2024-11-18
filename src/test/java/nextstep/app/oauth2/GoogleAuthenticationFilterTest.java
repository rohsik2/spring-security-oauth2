package nextstep.app.oauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import nextstep.app.domain.Member;
import nextstep.app.domain.MemberRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.contract.wiremock.AutoConfigureWireMock;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;

@ActiveProfiles("test")
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureWireMock(port = 8089)
class GoogleAuthenticationFilterTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private MemberRepository memberRepository;

    @BeforeEach
    void setupMockServer() throws Exception {
        UserStub userB = new UserStub("b", "b_access_token", "b@b.com", "b", "b_avatar_url");
        UserStub userC = new UserStub("c", "c_access_token", "c@c.com", "c", "c_avatar_url");

        setupUserStub(userB);
        setupUserStub(userC);
    }

    @ParameterizedTest
    @MethodSource("userProvider")
    void authenticationFilter(UserStub user) throws Exception {
        MockHttpSession session = new MockHttpSession();

        String state = mockMvc.perform(MockMvcRequestBuilders.get("/oauth2/authorization/google").session(session))
                .andExpect(MockMvcResultMatchers.status().is3xxRedirection())
                .andReturn().getResponse().getHeader(HttpHeaders.LOCATION).split("&state=")[1];

        String requestUri = "/login/oauth2/code/google?code=" + user.code + "&state=" + state;

        mockMvc.perform(MockMvcRequestBuilders.get(requestUri).session(session))
                .andDo(print())
                .andExpect(MockMvcResultMatchers.status().is3xxRedirection())
                .andExpect(MockMvcResultMatchers.redirectedUrl("/"));

        Member savedMember = memberRepository.findByEmail(user.email).get();
        assertThat(savedMember).isNotNull();
        assertThat(savedMember.getEmail()).isEqualTo(user.email);
        assertThat(savedMember.getName()).isEqualTo(user.name);
    }


    private void setupUserStub(UserStub user) throws Exception {
        Map<String, String> accessTokenResponseBody = new HashMap<>();
        accessTokenResponseBody.put("access_token", user.accessToken);
        accessTokenResponseBody.put("token_type", "bearer");
        String accessTokenJsonResponse = new ObjectMapper().writeValueAsString(accessTokenResponseBody);

        stubFor(post(urlEqualTo("/o/oauth2/token"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                        .withBody(accessTokenJsonResponse)));

        Map<String, String> userProfile = new HashMap<>();
        userProfile.put("email", user.email);
        userProfile.put("name", user.name);
        userProfile.put("picture", user.picture);
        String profileJsonResponse = new ObjectMapper().writeValueAsString(userProfile);

        stubFor(get(urlEqualTo("/oauth2/v1/userinfo"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                        .withBody(profileJsonResponse)));

    }

    static Stream<UserStub> userProvider() {
        return Stream.of(
                new UserStub("b", "b_access_token", "b@b.com", "b", "b_picture"),
                new UserStub("c", "c_access_token", "c@c.com", "c", "c_picture")
        );
    }

    static class UserStub {
        String code;
        String accessToken;
        String email;
        String name;
        String picture;

        public UserStub(String code, String accessToken, String email, String name, String picture) {
            this.code = code;
            this.accessToken = accessToken;
            this.email = email;
            this.name = name;
            this.picture = picture;
        }
    }
}
