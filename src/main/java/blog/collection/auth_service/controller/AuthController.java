package blog.collection.auth_service.controller;

import blog.collection.auth_service.common.AuthProvider;
import blog.collection.auth_service.common.CommonString;
import blog.collection.auth_service.dto.requestDTO.*;
import blog.collection.auth_service.dto.responseDTO.authResponseDTO.AddLocalAuthenticationUserResponseDTO;
import blog.collection.auth_service.dto.responseDTO.authResponseDTO.ChangePasswordResponseDTO;
import blog.collection.auth_service.dto.responseDTO.authResponseDTO.LocalLoginResponseDTO;
import blog.collection.auth_service.dto.responseDTO.authResponseDTO.ResetPasswordResponseDTO;
import blog.collection.auth_service.dto.responseDTO.commonResponse.BaseResponse;
import blog.collection.auth_service.entity.User;
import blog.collection.auth_service.security.CustomUserDetail;
import blog.collection.auth_service.security.JwtTokenProvider;
import blog.collection.auth_service.service.AuthenticationService;
import blog.collection.auth_service.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/blog-collection/auth")
@CrossOrigin("*")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationService authenticationService;
    private final UserService userService;
    private final RestTemplate restTemplate;
    private final RabbitTemplate rabbitTemplate;

    @Value("${queue.blacklist}")
    private String blacklistQueue;

    @PostMapping("/login")
    public ResponseEntity<BaseResponse<LocalLoginResponseDTO>> login(@RequestBody LoginDTO loginDTO) {
        return new ResponseEntity<>(authenticationService.loginLocalUser(loginDTO), HttpStatus.OK);
    }

    @PostMapping("/sign-up")
    public ResponseEntity<BaseResponse<String>> verifyEmail(@RequestBody AddLocalAuthenticationUserRequestDTO addLocalAuthenticationUserRequestDTO) {
        BaseResponse<String> response = authenticationService.verifyEmail(addLocalAuthenticationUserRequestDTO);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @GetMapping("/verify-email")
    public ResponseEntity<BaseResponse<AddLocalAuthenticationUserResponseDTO>> verifyEmail(@RequestParam("token") String token) {
        AddLocalAuthenticationUserResponseDTO response = authenticationService.addUserAuthentication(token);
        return new ResponseEntity<>(new BaseResponse<>(HttpStatus.OK.value(), CommonString.CREATE_NEW_USER_SUCCESSFULLY, response), HttpStatus.OK);
    }

    @GetMapping("/success")
    public ResponseEntity<BaseResponse<String>> loginByO2AuthSuccess(@AuthenticationPrincipal OAuth2User oAuth2User) {
        return new ResponseEntity<>(authenticationService.handleLoginSuccessByO2Auth(oAuth2User), HttpStatus.OK);
    }

    @GetMapping("/failure")
    public ResponseEntity<BaseResponse<String>> loginByO2AuthFail(@AuthenticationPrincipal OAuth2User oAuth2User) {
        return new ResponseEntity<>(new BaseResponse<>(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase(), CommonString.CAN_NOT_LOGIN_BY_GOOGLE), HttpStatus.UNAUTHORIZED);
    }

    @PostMapping("/reset/verify")
    public ResponseEntity<BaseResponse<String>> sendEmailToResetPassword(@RequestBody ResetPasswordRequestDTO resetPasswordRequestDTO) {
        return new ResponseEntity<>(userService.sendEmailToResetPassword(resetPasswordRequestDTO), HttpStatus.OK);
    }

    @GetMapping("/reset-password")
    public ResponseEntity<BaseResponse<ResetPasswordResponseDTO>> resetPassword(@RequestParam("token") String token, @RequestBody ResetPasswordDataDTO resetPasswordDataDTO) {
        return new ResponseEntity<>(userService.resetPassword(resetPasswordDataDTO, token), HttpStatus.OK);
    }

    @PostMapping("/change-password")
    public ResponseEntity<BaseResponse<ChangePasswordResponseDTO>> changePassword(@RequestHeader("X-Username") String username, @RequestBody ChangePasswordDataDTO changePasswordDataDTO) {
        return new ResponseEntity<>(userService.changePassword(changePasswordDataDTO, username), HttpStatus.OK);
    }

    @PostMapping("/logout")
    public ResponseEntity<BaseResponse<String>> logout(@RequestHeader("Authorization") String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new BaseResponse<>(HttpStatus.BAD_REQUEST.value(), "Invalid Authorization header", null));
        }

        String token = authorizationHeader.substring(7);

        rabbitTemplate.convertAndSend(blacklistQueue, token);

        return ResponseEntity.ok(new BaseResponse<>(HttpStatus.OK.value(), "Logout successful", null));
    }
}
