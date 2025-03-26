package blog.collection.auth_service.service;

import blog.collection.auth_service.dto.requestDTO.ChangePasswordDataDTO;
import blog.collection.auth_service.dto.requestDTO.ResetPasswordDataDTO;
import blog.collection.auth_service.dto.requestDTO.ResetPasswordRequestDTO;
import blog.collection.auth_service.dto.responseDTO.authResponseDTO.ChangePasswordResponseDTO;
import blog.collection.auth_service.dto.responseDTO.authResponseDTO.ResetPasswordResponseDTO;
import blog.collection.auth_service.dto.responseDTO.commonResponse.BaseResponse;

public interface UserService {
    BaseResponse<String> sendEmailToResetPassword(ResetPasswordRequestDTO resetPasswordRequestDTO);

    BaseResponse<ResetPasswordResponseDTO> resetPassword(ResetPasswordDataDTO resetPasswordDataDTO, String token);

    BaseResponse<ChangePasswordResponseDTO> changePassword(ChangePasswordDataDTO data);
}
