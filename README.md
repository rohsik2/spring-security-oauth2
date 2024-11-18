# spring-security

Github을 통한 로그인을 구현한다. 전체 과정을 수행하기 위해 아래 순서로 구현한다.

1. Github Application 등록
   Github 계정을 통한 인증을 구현하려면 우선 Github에서 OAuth App을 생성해야 한다. 다음 절차에 따라 Github에서 OAuth App을 등록하고 필요한 정보를 얻는다.

Github 가이드 문서를 참고해 OAuth Application을 생성한다.
Homepage URL: http://localhost:8080
Authorization callback URL: http://localhost:8080/login/oauth2/code/github
Client ID와 Client Secret을 기록해둔다.


2. 인증 URL 리다이렉트 필터 구현
   깃헙 로그인을 위해 깃헙 로그인 버튼을 누르면 깃헙 로그인 페이지로 이동해야한다. 이를 위해, 깃헙 로그인 페이지로 리다이렉트를 시키는 기능을 구현해야 한다.

GET /oauth2/authorization/github 요청 시 Github의 인증 URL로 리다이렉트시키는 필터를 구현한다.
Github의 인증 URL은 Github 가이드 문서와 다음의 예시를 참고하여 만든다.
https://github.com/login/oauth/authorize?response_type=code&client_id=클라이언트_ID&scope=read:user&redirect_uri=http://localhost:8080/login/oauth2/code/github


3. Github Access Token 획득
   리다이렉트된 URL로 이동하여 사용자가 Github 로그인을 마치면 승인 코드가 전달된다. 이 코드를 사용해 Github Access Token을 얻어야 한다.

GET /login/oauth2/code/github 요청 시 승인 코드를 받아 Access Token을 요청하는 필터를 작성한다.
Access Token 요청은 다음과 같이 구성된다.
POST https://github.com/login/oauth/access_token
필요한 파라미터는 Github 가이드 문서를 참고한다.


4. OAuth2 사용자 정보 조회
   Access Token을 획득한 후에는 Github API를 통해 사용자 정보를 가져와야 한다.

GET https://api.github.com/user 요청을 통해 사용자 정보를 가져오는 로직을 작성한다.
Access Token을 사용해 Github API에 인증된 요청을 보낸다. 자세한 내용은 Github 가이드 문서를 참고한다.


5. 후처리
   이후 프로필 정보를 가지고 회원 가입 & 로그인을 구현한다.
   기존 멤버 정보가 있는 경우 세션에 로그인 정보를 저장한 뒤 "/"으로 리다이렉트
   새로운 멤버인 경우 회원 가입 후 세션에 로그인 정보를 저장한 뒤 "/"으로 리다이렉트
