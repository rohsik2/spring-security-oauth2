package nextstep.app.oauth2;

import nextstep.app.SecurityConfig;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit.jupiter.SpringExtension;

//Spring의 container만 사용하겠다.
@ExtendWith(SpringExtension.class)
//특정 bean과 연관된 api들만 가져오겠다.
@Import(SecurityConfig.class)
public class TestExample {

}
