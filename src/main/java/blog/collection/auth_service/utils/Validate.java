package blog.collection.auth_service.utils;

import blog.collection.auth_service.common.CommonString;
import blog.collection.auth_service.dto.requestDTO.AddLocalAuthenticationUserRequestDTO;
import blog.collection.auth_service.dto.requestDTO.ChangePasswordDataDTO;
import blog.collection.auth_service.dto.requestDTO.ResetPasswordDataDTO;
import blog.collection.auth_service.exception.EmailVerificationException;
import blog.collection.auth_service.exception.InputValidationException;
import blog.collection.auth_service.exception.UserIsNotPresentException;
import blog.collection.auth_service.repository.UserAuthMethodRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.validation.BindingResult;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class Validate {
    private final UserAuthMethodRepository userAuthMethodRepository;
    private final RedisTemplate<String, Object> redisTemplate;
    private final PasswordEncoder passwordEncoder;

    public void validateInputData(String input, String regex, String errorMessage) {
        if (input == null || input.trim().isEmpty()) {
            throw new InputValidationException(CommonString.DATA_CAN_NOT_BE_NULL);
        }
        if (regex != null && !input.matches(regex)) {
            throw new InputValidationException(errorMessage);
        }
    }

    public void validateRegistrationInput(AddLocalAuthenticationUserRequestDTO requestDTO) {
        if (requestDTO == null) {
            throw new InputValidationException(CommonString.DATA_CAN_NOT_BE_NULL);
        }
        validateInputData(requestDTO.getPhoneNumber(), CommonString.PHONE_REGEX, CommonString.WRONG_PHONE_FORMAT);
        validateInputData(requestDTO.getEmail(), CommonString.EMAIL_REGEX, CommonString.WRONG_EMAIL_FORMAT);
        validateInputData(requestDTO.getPasswordHash(), CommonString.PASSWORD_FORMAT, CommonString.WRONG_PASSWORD_FORMAT);
    }

    public void validateAccountExisted(String username, String email) {
        validateInputData(username, null, CommonString.DATA_CAN_NOT_BE_NULL);
        validateInputData(email, CommonString.EMAIL_REGEX, CommonString.WRONG_EMAIL_FORMAT);
        if (!userAuthMethodRepository.existsByUsernameAndUserEmail(username, email)) {
            throw new UserIsNotPresentException(CommonString.CAN_NOT_FIND_ACCOUNT);
        }
    }

    public void validatePassword(String password) {
        validateInputData(password, CommonString.PASSWORD_FORMAT, CommonString.WRONG_PASSWORD_FORMAT);
    }

    public void validatePhone(String phone) {
        validateInputData(phone, CommonString.PHONE_REGEX, CommonString.WRONG_PHONE_FORMAT);
    }

    public void validateEmail(String email) {
        validateInputData(email, CommonString.EMAIL_REGEX, CommonString.WRONG_EMAIL_FORMAT);
    }

    public boolean validatePasswordMatching(String password1, String password2) {
        return password1.equals(password2);
    }

    public void validateInputDataForResetPassword(ResetPasswordDataDTO data) {
        if (data == null) {
            throw new InputValidationException(CommonString.DATA_CAN_NOT_BE_NULL);
        }
        validateInputData(data.getNewPassword(), CommonString.PASSWORD_FORMAT, CommonString.WRONG_PASSWORD_FORMAT);
        validateInputData(data.getConfirmNewPassword(), null, CommonString.DATA_CAN_NOT_BE_NULL);
        if (!validatePasswordMatching(data.getNewPassword(), data.getConfirmNewPassword())) {
            throw new InputValidationException(CommonString.CONFIRM_PASSWORD_MUST_SAME);
        }
    }

    public void validateInputDataForChangePassword(ChangePasswordDataDTO data, String currentPassword) {
        if (data == null) {
            throw new InputValidationException(CommonString.DATA_CAN_NOT_BE_NULL);
        }
        validateInputData(data.getCurrentPassword(), null, CommonString.DATA_CAN_NOT_BE_NULL);
        validateInputData(data.getNewPassword(), CommonString.PASSWORD_FORMAT, CommonString.WRONG_PASSWORD_FORMAT);
        validateInputData(data.getConfirmNewPassword(), null, CommonString.DATA_CAN_NOT_BE_NULL);
        if (!validatePasswordMatching(data.getNewPassword(), data.getConfirmNewPassword())) {
            throw new InputValidationException(CommonString.CONFIRM_PASSWORD_MUST_SAME);
        }
        if (!passwordEncoder.matches(data.getCurrentPassword(), currentPassword)) {
            throw new InputValidationException(CommonString.CURRENT_PASSWORD_WRONG);
        }
    }

    public <T> T verifyToken(String token, Class<T> targetClass) {
        T data = targetClass.cast(redisTemplate.opsForValue().get(token));
        if (data == null) {
            throw new EmailVerificationException(CommonString.EXPIRED_EMAIL_VERIFY_LINK);
        }
        redisTemplate.delete(token);
        return data;
    }
}
