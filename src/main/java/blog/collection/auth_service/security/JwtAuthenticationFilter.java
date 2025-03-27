//package blog.collection.auth_service.security;
//
//import blog.collection.auth_service.common.CommonString;
//import blog.collection.auth_service.common.RoleName;
//import blog.collection.auth_service.exception.AuthenticationFailException;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//
//import lombok.RequiredArgsConstructor;
//
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
//import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
//import org.springframework.util.StringUtils;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//import java.util.Collections;
//
//@RequiredArgsConstructor
//public class JwtAuthenticationFilter extends OncePerRequestFilter {
//
//    private final JwtTokenProvider jwtTokenProvider;
//
//    private final CustomUserDetailService customUserDetailService;
//
//    private final BlackListToken blackListToken;
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//        try {
//            String jwt = jwtTokenProvider.getTokenFromRequest(request);
//            if (jwt != null) {
//                if (blackListToken.isTokenBlackList(jwt)) {
//                    throw new AuthenticationFailException("Token không hợp lệ hoặc bị chặn");
//                }
//                if (!jwtTokenProvider.validateToken(jwt)) {
//                    throw new AuthenticationFailException("Token không hợp lệ hoặc bị chặn");
//                }
//
//                String username = jwtTokenProvider.getUsernameFromToken(jwt);
//                if (username == null) {
//                    throw new AuthenticationFailException("Token không chứa thông tin người dùng");
//                }
//
//                String authProvider = jwtTokenProvider.getClaimFromToken(jwt, "auth_provider");
//                if ("LOCAL".equalsIgnoreCase(authProvider)) {
//                    UserDetails userDetails = customUserDetailService.loadUserByUsername(username);
//                    if (userDetails == null) {
//                        throw new AuthenticationFailException("Không tìm thấy người dùng local");
//                    }
//                    setAuthentication(userDetails, request);
//                } else {
//                    DefaultOAuth2User oAuth2User = new DefaultOAuth2User(
//                            Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
//                            Collections.singletonMap("email", username),
//                            "email"
//                    );
//                    setAuthentication(oAuth2User, request);
//                }
//            }
//        } catch (Exception e) {
//            throw new AuthenticationFailException(CommonString.FAIL_TO_AUTHENTICATE);
//        }
//        filterChain.doFilter(request, response);
//    }
//
//    private void setAuthentication(Object principal, HttpServletRequest request) {
//        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
//                principal, null, ((UserDetails) principal).getAuthorities()
//        );
//        auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//        SecurityContextHolder.getContext().setAuthentication(auth);
//    }
//}
