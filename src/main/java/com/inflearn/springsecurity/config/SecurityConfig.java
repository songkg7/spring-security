package com.inflearn.springsecurity.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Slf4j
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 인가 정책
        http
                .authorizeRequests()
                .anyRequest().authenticated();

        // 인증 정책
        http
                .formLogin();

        // 동시세션제어
        http
                .sessionManagement()
                // .sessionFixation().none() // 세션 고정 보호 해제, 보안에 취약해지기 때문에 기본값은 changeSessionId 로 되어 있다.
                .maximumSessions(1)
                .maxSessionsPreventsLogin(true);  // default false

    }

}
