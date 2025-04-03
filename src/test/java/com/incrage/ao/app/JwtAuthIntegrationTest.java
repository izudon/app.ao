package com.incrage.ao.app;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot
    .test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.security
    .authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.MockMvc;

import com.incrage.ao.common.JwtTokenProvider;

import jakarta.servlet.http.Cookie;

import static org.springframework.test.web.servlet.request
    .MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result
    .MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class JwtAuthIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Test // 正常
    void access_withValidJwt_returns200() throws Exception {
        Authentication auth
	    = new UsernamePasswordAuthenticationToken("testuser", null);
        String token = jwtTokenProvider.createToken(auth);

        mockMvc.perform(get("/api/hello")
                .cookie(new Cookie("JWT_TOKEN", token)))
                .andExpect(status().isOk());
    }

    @Test // 異常：JWT の設定なし
    void access_withNoJwt_returns401() throws Exception {
        mockMvc.perform(get("/api/hello"))
                .andExpect(status().isUnauthorized());
    }

    @Test // 異常：JWT が不正
    void access_withInvalidJwt_returns401() throws Exception {
        mockMvc.perform(get("/api/hello")
                .cookie(new Cookie("JWT_TOKEN", "invalid-token")))
                .andExpect(status().isUnauthorized());
    }
}
