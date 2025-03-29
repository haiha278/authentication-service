package blog.collection.auth_service.service;

import blog.collection.auth_service.common.AuthProvider;
import blog.collection.auth_service.common.CommonString;
import blog.collection.auth_service.dto.requestDTO.ChangePasswordDataDTO;
import blog.collection.auth_service.dto.requestDTO.ResetPasswordDataDTO;
import blog.collection.auth_service.dto.requestDTO.ResetPasswordRequestDTO;
import blog.collection.auth_service.dto.responseDTO.authResponseDTO.ChangePasswordResponseDTO;
import blog.collection.auth_service.dto.responseDTO.authResponseDTO.ResetPasswordResponseDTO;
import blog.collection.auth_service.dto.responseDTO.commonResponse.BaseResponse;
import blog.collection.auth_service.entity.UserAuthMethod;
import blog.collection.auth_service.exception.EmailVerificationException;
import blog.collection.auth_service.exception.InputValidationException;
import blog.collection.auth_service.exception.UserIsNotPresentException;
import blog.collection.auth_service.mapper.Mapper;
import blog.collection.auth_service.repository.UserAuthMethodRepository;
import blog.collection.auth_service.repository.UserRepository;
import blog.collection.auth_service.utils.EmailUtils;
import blog.collection.auth_service.utils.Validate;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final EmailUtils emailUtils;
    private final UserRepository userRepository;
    private final UserAuthMethodRepository userAuthMethodRepository;
    private final Validate validate;
    private final PasswordEncoder passwordEncoder;

    @Override
    public BaseResponse<String> sendEmailToResetPassword(ResetPasswordRequestDTO resetPasswordRequestDTO) {
        try {
            validate.validateAccountExisted(resetPasswordRequestDTO.getUsername(), resetPasswordRequestDTO.getEmail());
            emailUtils.sentToResetPassword(resetPasswordRequestDTO);
        } catch (MessagingException e) {
            throw new EmailVerificationException(CommonString.CAN_NOT_SEND_EMAIL);
        }
        return new BaseResponse<>(HttpStatus.OK.value(), HttpStatus.OK.getReasonPhrase(), CommonString.SEND_MESSAGE_TO_EMAIL_SUCCESSFULLY);
    }

    @Override
    public BaseResponse<ResetPasswordResponseDTO> resetPassword(ResetPasswordDataDTO resetPasswordDataDTO, String token) {
        ResetPasswordRequestDTO resetPasswordRequestDTO = validate.verifyToken(token, ResetPasswordRequestDTO.class);

        validate.validateInputDataForResetPassword(resetPasswordDataDTO);

        UserAuthMethod userAuthMethod = userAuthMethodRepository.findByUsernameAndAuthProviderAndUserEmail(resetPasswordRequestDTO.getUsername(), AuthProvider.LOCAL, resetPasswordRequestDTO.getEmail())
                .orElseThrow(() -> new UserIsNotPresentException(CommonString.CAN_NOT_FIND_ACCOUNT));

        userAuthMethod.setPasswordHash(passwordEncoder.encode(resetPasswordDataDTO.getNewPassword()));
        userAuthMethod.setUpdateAt(LocalDateTime.now().toString());

        UserAuthMethod response = userAuthMethodRepository.save(userAuthMethod);

        ResetPasswordResponseDTO resetPasswordResponseDTO = ResetPasswordResponseDTO.builder()
                .updateAt(LocalDateTime.parse(response.getUpdateAt(), DateTimeFormatter.ISO_LOCAL_DATE_TIME))
                .userId(response.getId())
                .build();
        return new BaseResponse<>(HttpStatus.OK.value(), CommonString.RESET_PASSWORD_SUCCESSFULLY, resetPasswordResponseDTO);
    }

    @Override
    public BaseResponse<ChangePasswordResponseDTO> changePassword(ChangePasswordDataDTO data, String username) {
        UserAuthMethod userAuthMethod = userAuthMethodRepository.findByUsernameAndAuthProvider(username, AuthProvider.LOCAL)
                .orElseThrow(() -> new UserIsNotPresentException(CommonString.CAN_NOT_FIND_ACCOUNT));

        validate.validateInputDataForChangePassword(data, userAuthMethod.getPasswordHash());

        userAuthMethod.setPasswordHash(passwordEncoder.encode(data.getNewPassword()));
        UserAuthMethod savedData = userAuthMethodRepository.save(userAuthMethod);
        ChangePasswordResponseDTO responseData = ChangePasswordResponseDTO.builder()
                .id(savedData.getId())
                .updateAt(LocalDateTime.parse(savedData.getUpdateAt(), DateTimeFormatter.ISO_LOCAL_DATE_TIME))
                .build();
        return new BaseResponse<>(HttpStatus.OK.value(), CommonString.CHANGE_PASSWORD_SUCCESSFULLY, responseData);
    }

}
