package com.cos.security1.controller;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.parameters.P;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpSession;

@Controller
@Slf4j
public class IndexController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/test/login")
    public @ResponseBody String TestLogin(Authentication authentication, @AuthenticationPrincipal PrincipalDetails userDetails){
        System.out.println("/test/login===============");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("principalDetails.getUser:" + principalDetails.getUser());

        System.out.println("userDetails : "+principalDetails.getUser());
        return "세션 정보 확인하기";
    }

    @GetMapping("/test/oauth/login")
    public @ResponseBody String TestOAuthLogin(Authentication authentication,@AuthenticationPrincipal OAuth2User oauth){
        System.out.println("/test/oauth/login===============");
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("authentication:" + oauth2User.getAttributes());
        System.out.println("oauthUser:" + oauth.getAttributes());
        return "OAuth 세션 정보 확인하기";
    }

    @GetMapping({ "", "/" })
    public String index() {
        return "index";
    }

    //OAuth로그인을 해도 PrincipalDetails
    //일반 로그인을 해도 PrincipalDetails
    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails){
        System.out.println("principalDetails:" + principalDetails.getUser());
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin(){
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager(){
        return "manager";
    }

    //시큐리티가 해당 주소를 낚아챔
    // -> securityConfig 파일 생성 후 작동 안함
    @GetMapping("/loginForm")
    public String loginForm(@ModelAttribute User user, HttpSession session){
        if (session.getAttribute("SPRING_SECURITY_CONTEXT") != null) {
            return "redirect:/";
        }
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }

    @PostMapping("/join")
    public  String join(User user){
        log.info("user ={}" ,user);
        //패스워드 암호화
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        user.setRole("ROLE_USER");
        userRepository.save(user);
        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info(){
        return "개인정보";
    }

    //여러개 걸고 싶으면 이게 좋음 //postAuthorize는 잘 안씀
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    public @ResponseBody String data(){
        return "개인정보";
    }

}
