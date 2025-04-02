package com.incrage.ao.app;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.List;

@Component
public class JwtTokenProvider {

    private final Key secretKey;
    private final long expirationMs;

    public JwtTokenProvider(
        @Value("${jwt.secret-key}") String secret,
        @Value("${jwt.expiration-ms}") long expirationMs
    ) {
        this.secretKey
	    = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expirationMs = expirationMs;
    }

    // 認証（Authentication）オブジェクトからトークンを作成
    public String createToken(Authentication authentication) {
        String subject = authentication.getName();
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    // リクエストからトークンを取り出す（from Cookie with name "JWT_TOKEN"）
    public String resolveToken(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        for (Cookie cookie : request.getCookies()) {
            if ("JWT_TOKEN".equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    // トークンを検証（署名・有効期限）
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(secretKey)
		.build().parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    // トークンから認証情報を取り出す（ここでは簡易的に username のみ使用）
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        String username = claims.getSubject();
        User principal = new User(username, "", List.of());
        return new UsernamePasswordAuthenticationToken
	    (principal, token, principal.getAuthorities());
    }
}
