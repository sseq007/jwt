package com.ssafy.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ssafy.jwt.config.auth.PrincipalDetails;
import com.ssafy.jwt.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

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

        try {
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println("user = " + user);
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            //PrincipalDetailsService의 loadUserByUsername() 함수 실행된 후 정상이면 authetication이 리턴됨

            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("principal.getUsername() = " + principal.getUser().getUsername());
            //2. 정상인지 로그인 시도를 해본다 authenticationManager로 로그인 시도를 하면 principalDetailservice 실행
            return authentication;
        } catch (Exception e) {

        }


        //3 PrincipalDetails를 세션에 담는다(권한 관리를 위해 필요없으면 삭제)
        //4. JWT토큰을 만들어서 응답

        return null;
    }

    // JWT Token 생성해서 response에 담아주기
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        System.out.println("로그인이 되었다는 뜻");
        PrincipalDetails principalDetailis = (PrincipalDetails) authResult.getPrincipal();

        //RSA방식은 아니구 Hash암호방식
        String jwtToken = JWT.create()
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis()+(60000*10)))
                .withClaim("id", principalDetailis.getUser().getId())
                .withClaim("username", principalDetailis.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));


        response.addHeader("Authorization","Bearer "+jwtToken);
    }
}
