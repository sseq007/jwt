package com.ssafy.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        //토큰 : 코스
        if (req.getMethod().equals("POST")) {
            String headerAuth = req.getHeader("Authorization");
            System.out.println("필터1");
            System.out.println(headerAuth);

            if (headerAuth.equals("cos")) {
                chain.doFilter(req, res);
            } else {
                PrintWriter writer = res.getWriter();
                writer.println("인증안됨");
            }
        }

    }
}
