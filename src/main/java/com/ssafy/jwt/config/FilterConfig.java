package com.ssafy.jwt.config;

import com.ssafy.jwt.filter.MyFilter1;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<MyFilter1> filter1() {
        FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
        bean.addUrlPatterns("/**1");
        bean.setOrder(0); // 낮은 번호가 필터중에서 가장 먼저 실행됨
        return bean;
    }
}

