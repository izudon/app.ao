package com.incrage.ao.app;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config
    .annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config
    .annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web
    .authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security
    .config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security
    .config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security
    .config.annotation.web.configurers.LogoutConfigurer;
import com.incrage.ao.common.JwtAuthenticationFilter;
import com.incrage.ao.common.JwtAuthenticationEntryPoint;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    public SecurityConfig(
        JwtAuthenticationFilter jwtAuthenticationFilter,
        JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint
    ) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http)
	throws Exception {
	
        http

	    // 不要な認証機能等を disable
	    .csrf(csrf -> csrf.disable())       // CSRF 無効
	    .with(new FormLoginConfigurer<HttpSecurity>()
		  , config -> config.disable()) // フォームログイン無効
	    .with(new HttpBasicConfigurer<HttpSecurity>()
		  , config -> config.disable()) // Basic認証無効
	    .with(new LogoutConfigurer<HttpSecurity>()
		  , config -> config.disable()) // ログアウト機能無効

	    // 認証設定
            .authorizeHttpRequests(authz -> authz
                .anyRequest().authenticated()
            )
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
            )
            .addFilterBefore(jwtAuthenticationFilter,
			     UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
