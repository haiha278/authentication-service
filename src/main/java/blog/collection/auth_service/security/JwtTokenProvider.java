package blog.collection.auth_service.security;

import blog.collection.auth_service.common.AuthProvider;

import io.jsonwebtoken.*;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtTokenProvider {
    @Value("${ra.jwt.secret}")
    private String SECRET_KEY;
    @Value("${ra.jwt.expiration}")
    private Long JWT_EXPIRATION;
    @Value("${ra.jwt.refresh-secret}")
    private String REFRESH_SECRET_KEY;
    @Value("${ra.jwt.refresh-expiration}")
    private Long REFRESH_JWT_EXPIRATION;

    public String generateToken(String username, AuthProvider authProvider, Long userId, Long userAuthMethodId) {
        Date now = new Date();
        Map<String, Object> claims = new HashMap<>();
        claims.put("auth_provider", authProvider.name());
        claims.put("user_id", userId);
        claims.put("user_auth_method_id", userAuthMethodId);
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + JWT_EXPIRATION))
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY.getBytes())
                .compact();
    }

    public String generateRefreshToken(String username, AuthProvider authProvider, Long userId, Long userAuthMethodId) {
        Date now = new Date();
        Map<String, Object> claims = new HashMap<>();
        claims.put("auth_provider", authProvider.name());
        claims.put("user_id", userId);
        claims.put("user_auth_method_id", userAuthMethodId);
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + REFRESH_JWT_EXPIRATION))
                .signWith(SignatureAlgorithm.HS256, REFRESH_SECRET_KEY.getBytes())
                .compact();
    }
}
