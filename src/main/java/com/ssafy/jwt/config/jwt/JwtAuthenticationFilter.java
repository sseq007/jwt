package com.ssafy.jwt.config.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

//스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
//login 요쳥해서 username,password 전송하면(post)
//UsernamePasswordAuthenticationFilter 발동

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    //login 요청을 하면 로그인 시도를 위해서 실행되는 함수

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        System.out.println("로그인 시도중");

        //1. username password 받아서

        //2. 정상인지 로그인 시도를 해본다 authenticationManager로 로그인 시도를 하면 principalDetailservice 실행

        //3 PrincipalDetails를 세션에 담는다(권한 관리를 위해 필요없으면 삭제)
        //4. JWT토큰을 만들어서 응답

        return super.attemptAuthentication(request, response);
    }
}
