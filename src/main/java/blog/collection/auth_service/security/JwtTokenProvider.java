package blog.collection.auth_service.security;

import blog.collection.auth_service.common.AuthProvider;
import blog.collection.auth_service.common.CommonString;
import blog.collection.auth_service.exception.JwtValidationException;
import io.jsonwebtoken.*;
import jakarta.servlet.http.HttpServletRequest;
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

//    public String getClaimFromToken(String token, String claimName) {
//        Claims claims = Jwts.parserBuilder()
//                .setSigningKey(SECRET_KEY.getBytes())
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//        return claims.get(claimName, String.class);
//    }
//
//    public String getUsernameFromToken(String token) {
//        Claims claims = Jwts.parserBuilder()
//                .setSigningKey(SECRET_KEY.getBytes())
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//        return claims.getSubject();
//    }
//
//    public boolean validateToken(String token) {
//        try {
//            Jwts.parserBuilder()
//                    .setSigningKey(SECRET_KEY.getBytes())
//                    .build()
//                    .parseClaimsJws(token);
//            return true;
//        } catch (ExpiredJwtException e) {
//            throw new JwtValidationException(CommonString.EXPIRED_TOKEN);
//        } catch (UnsupportedJwtException e) {
//            throw new JwtValidationException(CommonString.UNSUPPORTED_TOKEN);
//        } catch (MalformedJwtException e) {
//            throw new JwtValidationException(CommonString.TOKEN_FORMAT_NOT_CORRECT);
//        } catch (SignatureException e) {
//            throw new JwtValidationException(CommonString.INVALID_TOKEN);
//        } catch (IllegalArgumentException e) {
//            throw new JwtValidationException(CommonString.TOKEN_IS_EMPTY);
//        }
//    }

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

//    public String getUsernameFromRefreshToken(String token) {
//        Claims claims = Jwts.parserBuilder()
//                .setSigningKey(REFRESH_SECRET_KEY.getBytes())
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//        return claims.getSubject();
//    }
//
//    public boolean validateRefreshToken(String token) {
//        try {
//            Jwts.parserBuilder()
//                    .setSigningKey(REFRESH_SECRET_KEY.getBytes())
//                    .build()
//                    .parseClaimsJws(token);
//            return true;
//        } catch (ExpiredJwtException e) {
//            throw new JwtValidationException(CommonString.EXPIRED_TOKEN);
//        } catch (UnsupportedJwtException e) {
//            throw new JwtValidationException(CommonString.UNSUPPORTED_TOKEN);
//        } catch (MalformedJwtException e) {
//            throw new JwtValidationException(CommonString.TOKEN_FORMAT_NOT_CORRECT);
//        } catch (SignatureException e) {
//            throw new JwtValidationException(CommonString.INVALID_TOKEN);
//        } catch (IllegalArgumentException e) {
//            throw new JwtValidationException(CommonString.TOKEN_IS_EMPTY);
//        }
//    }
//
//    public String getTokenFromRequest(HttpServletRequest request) {
//        String bearerToken = request.getHeader("Authorization");
//        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
//            return bearerToken.substring(7);
//        }
//        return null;
//    }
//
//    public long getTimeRemainingOfToken(String token) {
//        Claims claims = Jwts.parserBuilder()
//                .setSigningKey(SECRET_KEY.getBytes())
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//        return claims.getExpiration().getTime() - System.currentTimeMillis();
//    }
}
