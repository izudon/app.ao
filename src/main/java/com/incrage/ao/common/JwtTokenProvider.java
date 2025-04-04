package com.incrage.ao.common;

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

    private final Key primaryKey;
    private final Key spareKey;
    private final long expirationMs;

    public JwtTokenProvider(
        @Value("${app.jwt.secret-key}") String secret,
        @Value("${app.jwt.secret-key-spare}") String spare,
        @Value("${app.jwt.expiration-ms}") long expirationMs
    ) {
        this.primaryKey
	    = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.spareKey
	    = Keys.hmacShaKeyFor(spare.getBytes(StandardCharsets.UTF_8));
        this.expirationMs = expirationMs;
    }

    // トークン作成は primaryKey のみ使用
    public String createToken(Authentication authentication) {
        String subject = authentication.getName();
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(primaryKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public String resolveToken(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        for (Cookie cookie : request.getCookies()) {
            if ("JWT_TOKEN".equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    public boolean validateToken(String token) {
        return parseClaims(token) != null;
    }

    public Authentication getAuthentication(String token) {
        Claims claims = parseClaims(token);
        if (claims == null) throw new JwtException("Invalid token");

        String username = claims.getSubject();
        User principal = new User(username, "", List.of());
        return new UsernamePasswordAuthenticationToken
	    (principal, token, principal.getAuthorities());
    }

    private Claims parseClaims(String token) {
	List<Key> keys = List.of(primaryKey, spareKey);

	for (Key key : keys) {
	    try {
		return Jwts.parserBuilder()
		    .setSigningKey(key)
		    .build()
		    .parseClaimsJws(token)
		    .getBody();
	    } catch (JwtException | IllegalArgumentException ignored) {
		// 次の鍵に進む
	    }
	}

	return null; // どの鍵でも検証できなかった場合
    }
}
