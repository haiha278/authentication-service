package blog.collection.auth_service.service;

import blog.collection.auth_service.dto.requestDTO.AddLocalAuthenticationUserRequestDTO;
import blog.collection.auth_service.dto.requestDTO.LoginDTO;
import blog.collection.auth_service.dto.responseDTO.authResponseDTO.AddLocalAuthenticationUserResponseDTO;
import blog.collection.auth_service.dto.responseDTO.authResponseDTO.LocalLoginResponseDTO;
import blog.collection.auth_service.dto.responseDTO.commonResponse.BaseResponse;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;

public interface AuthenticationService {
    AddLocalAuthenticationUserResponseDTO addUserAuthentication(String token);

    BaseResponse<String> verifyEmail(AddLocalAuthenticationUserRequestDTO addLocalAuthenticationUserRequestDTO);

    BaseResponse<String> handleLoginSuccessByO2Auth(OAuth2User oAuth2User);

    BaseResponse<LocalLoginResponseDTO> loginLocalUser(LoginDTO loginDTO);
}
