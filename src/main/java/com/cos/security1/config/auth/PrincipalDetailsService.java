package com.cos.security1.config.auth;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

//시큐리티 설정에서 loginProcessingUrl("/login");
//login요청이 오면 자동으로 UserDetailService 타입으로 Ioc되어있는 loadUserByUsername 함수가 실행된다.
//loc --> 객체의 권한을 개발자가 아닌 스프링에게 넘기는 것
@Service
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    //시큐리티 session(내부 Authentication)  = Authentication(내부 UserDetails) = UserDetails
    //함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어 진다.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = userRepository.findByUsername(username);
        if(username != null){
            return new PrincipalDetails(userEntity);
        }
        return null;
    }
}
