package nextstep.oauth2.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nextstep.oauth2.OAuth2AuthenticationException;
import nextstep.oauth2.OAuth2AuthorizedClient;
import nextstep.oauth2.authentication.OAuth2AuthenticationToken;
import nextstep.oauth2.authentication.OAuth2LoginAuthenticationToken;
import nextstep.oauth2.endpoint.OAuth2AuthorizationExchange;
import nextstep.oauth2.endpoint.OAuth2AuthorizationRequest;
import nextstep.oauth2.endpoint.OAuth2AuthorizationResponse;
import nextstep.oauth2.endpoint.OAuth2AuthorizationResponseUtils;
import nextstep.oauth2.registration.ClientRegistration;
import nextstep.oauth2.registration.ClientRegistrationRepository;
import nextstep.security.authentication.AbstractAuthenticationProcessingFilter;
import nextstep.security.authentication.Authentication;
import nextstep.security.authentication.AuthenticationManager;
import org.springframework.core.convert.converter.Converter;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;

public class OAuth2LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final String DEFAULT_LOGIN_REQUEST_BASE_URI = "/login/oauth2/code/";

    private final ClientRegistrationRepository clientRegistrationRepository;

    private final OAuth2AuthorizedClientRepository authorizedClientRepository;

    private final AuthorizationRequestRepository authorizationRequestRepository = new AuthorizationRequestRepository();

    private final Converter<OAuth2LoginAuthenticationToken, OAuth2AuthenticationToken> authenticationResultConverter = this::createAuthenticationResult;

    public OAuth2LoginAuthenticationFilter(ClientRegistrationRepository clientRegistrationRepository, OAuth2AuthorizedClientRepository authorizedClientRepository, AuthenticationManager authenticationManager) {
        super(DEFAULT_LOGIN_REQUEST_BASE_URI, authenticationManager);
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizedClientRepository = authorizedClientRepository;
    }

    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

        // request에서 parameter를 가져오기
        MultiValueMap<String, String> params = OAuth2AuthorizationResponseUtils.toMultiMap(request.getParameterMap());
        if (!OAuth2AuthorizationResponseUtils.isAuthorizationResponse(params)) {
            throw new OAuth2AuthenticationException();
        }

        // session에서 authorizationRequest를 가져오기
        OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository.removeAuthorizationRequest(request, response);
        if (authorizationRequest == null) {
            throw new OAuth2AuthenticationException();
        }

        // registrationId를 가져오고 clientRegistration을 가져오기
        String registrationId = extractRegistrationId(request);
        ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
        if (clientRegistration == null) {
            throw new OAuth2AuthenticationException();
        }

        // code를 포함한 authorization response를 객체로 가져오기
        OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponseUtils.convert(params,
                clientRegistration.getRedirectUri());

        // access token 을 가져오기 위한 request 객체 만들기
        OAuth2LoginAuthenticationToken authenticationRequest = new OAuth2LoginAuthenticationToken(clientRegistration,
                new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));

        // OAuth2LoginAuthenticationToken 만들기
        OAuth2LoginAuthenticationToken authenticationResult = (OAuth2LoginAuthenticationToken) getAuthenticationManager()
                .authenticate(authenticationRequest);

        // provider 인증 후 authenticated된 OAuth2AuthenticationToken 객체 가져오기
        OAuth2AuthenticationToken oauth2Authentication = this.authenticationResultConverter.convert(authenticationResult);
        Assert.notNull(oauth2Authentication, "authentication result cannot be null");

        // authorizedClientRepository 에 저장할 OAuth2AuthorizedClient을 만들고 저장
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
                authenticationResult.getClientRegistration(), oauth2Authentication.getName(), authenticationResult.getAccessToken());

        this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, oauth2Authentication, request, response);

        return oauth2Authentication;
    }

    private String extractRegistrationId(HttpServletRequest request) {
        String uri = request.getRequestURI();

        if (uri.startsWith(DEFAULT_LOGIN_REQUEST_BASE_URI)) {
            return uri.substring(DEFAULT_LOGIN_REQUEST_BASE_URI.length());
        }

        return null;
    }

    private OAuth2AuthenticationToken createAuthenticationResult(OAuth2LoginAuthenticationToken authenticationResult) {
        return new OAuth2AuthenticationToken(authenticationResult.getPrincipal(), authenticationResult.getAuthorities());
    }
}
