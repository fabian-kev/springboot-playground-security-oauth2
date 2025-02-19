package com.fabiankevin.springboot_oaut2_login_and_client.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class OAuth2ClientSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authorize) -> {
                    authorize.requestMatchers("/").permitAll();
                    authorize.anyRequest().authenticated();
                })
                .oauth2Login(withDefaults())
//                .oauth2Login(oauth2LoginConfigurer -> oauth2LoginConfigurer
//                        .defaultSuccessUrl("/", true))
                .oauth2Client(Customizer.withDefaults());
        return http.build();
    }
}