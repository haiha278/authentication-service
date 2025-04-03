package blog.collection.auth_service.service;

import blog.collection.auth_service.dto.requestDTO.*;
import blog.collection.auth_service.dto.responseDTO.authResponseDTO.AddLocalAuthenticationUserResponseDTO;
import blog.collection.auth_service.dto.responseDTO.authResponseDTO.ChangePasswordResponseDTO;
import blog.collection.auth_service.dto.responseDTO.authResponseDTO.LocalLoginResponseDTO;
import blog.collection.auth_service.dto.responseDTO.authResponseDTO.ResetPasswordResponseDTO;
import blog.collection.auth_service.dto.responseDTO.commonResponse.BaseResponse;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;

public interface AuthenticationService {
    AddLocalAuthenticationUserResponseDTO addUserAuthentication(String token);

    BaseResponse<String> verifyEmail(AddLocalAuthenticationUserRequestDTO addLocalAuthenticationUserRequestDTO);

    BaseResponse<String> sendEmailToResetPassword(ResetPasswordRequestDTO resetPasswordRequestDTO);

    BaseResponse<ResetPasswordResponseDTO> resetPassword(ResetPasswordDataDTO resetPasswordDataDTO, String token);

    BaseResponse<ChangePasswordResponseDTO> changePassword(ChangePasswordDataDTO data, String username);

    BaseResponse<String> handleLoginSuccessByO2Auth(OAuth2User oAuth2User);

    BaseResponse<LocalLoginResponseDTO> loginLocalUser(LoginDTO loginDTO);
}
