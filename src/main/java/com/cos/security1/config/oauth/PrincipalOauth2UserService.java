package com.cos.security1.config.oauth;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.oauth.provider.FacebookUserInfo;
import com.cos.security1.config.oauth.provider.GoogleUserInfo;
import com.cos.security1.config.oauth.provider.NaverUserInfo;
import com.cos.security1.config.oauth.provider.OAuth2UserInfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    UserRepository userRepository;

    //구글로부터 받은 userRequest 데이터에 대한 후처리 함수
    //함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어 진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("getClientRegistration:" + userRequest.getClientRegistration());
        System.out.println("getAccessToken.getTokenValue:" + userRequest.getAccessToken().getTokenValue());

        OAuth2User oauth2User = super.loadUser(userRequest);
        //구글 로그인 클릭 -> 구글로그인창->로그인 완료-> code를 리턴(OAuth-Client라이브러리가 받아줌)->AccessToken을 요청
        //여기까지가 userRequest정보 -> 회원프로필을 받아야함 -> 이떄 사용되는 함수 loadUser함수 -> 회원프로필
        System.out.println("getAttributes:" + oauth2User.getAttributes());

        //회원가입 강제 진행
        OAuth2UserInfo oAuth2UserInfo = null;
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            System.out.println("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oauth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("facebook")){
            System.out.println("페이스북 로그인 요청");
            oAuth2UserInfo = new FacebookUserInfo(oauth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")){
            System.out.println("네이버 로그인 요청");
            oAuth2UserInfo = new NaverUserInfo((Map)oauth2User.getAttributes().get("response"));
        }
        else{
            System.out.println("우리는 구글과 페이스북과 네이버만 지원합니다.");
        }


        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider+"_"+providerId; //google_1079428561829~~
        String email = oAuth2UserInfo.getEmail();
        String password = bCryptPasswordEncoder.encode("겟인데어");
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);
        System.out.println("OAuth 로그인이 최초입니다.");
        if(userEntity == null){
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }else{
            System.out.println("로그인을 이미 한적이 있습니다. 당신은 자동회원가입이 되어 있습니다.");
        }


        return new PrincipalDetails(userEntity,oauth2User.getAttributes());
    }
}
