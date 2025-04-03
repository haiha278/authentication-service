package blog.collection.auth_service.service;

import blog.collection.auth_service.common.AuthProvider;
import blog.collection.auth_service.common.CommonString;
import blog.collection.auth_service.common.RoleName;
import blog.collection.auth_service.dto.requestDTO.*;
import blog.collection.auth_service.dto.responseDTO.authResponseDTO.AddLocalAuthenticationUserResponseDTO;
import blog.collection.auth_service.dto.responseDTO.authResponseDTO.ChangePasswordResponseDTO;
import blog.collection.auth_service.dto.responseDTO.authResponseDTO.LocalLoginResponseDTO;
import blog.collection.auth_service.dto.responseDTO.authResponseDTO.ResetPasswordResponseDTO;
import blog.collection.auth_service.dto.responseDTO.commonResponse.BaseResponse;
import blog.collection.auth_service.dto.tranferMessage.CreateUserTransferMessage;
import blog.collection.auth_service.entity.UserAuthMethod;
import blog.collection.auth_service.exception.*;
import blog.collection.auth_service.mapper.Mapper;
import blog.collection.auth_service.repository.RoleRepository;
import blog.collection.auth_service.repository.UserAuthMethodRepository;
import blog.collection.auth_service.security.JwtTokenProvider;
import blog.collection.auth_service.utils.EmailUtils;
import blog.collection.auth_service.utils.Validate;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.authentication.BadCredentialsException;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;


@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationServiceImpl implements AuthenticationService {
    private final UserAuthMethodRepository userAuthMethodRepository;
    private final RoleRepository roleRepository;
    private final EmailUtils emailUtils;
    private final Validate validate;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    private final AuthenticationManager authenticationManager;
    private final RabbitTemplate rabbitTemplate;
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationServiceImpl.class);

    private void sendVerificationEmail(AddLocalAuthenticationUserRequestDTO userData) throws MessagingException {
        emailUtils.sendToVerifyEmail(userData);
    }

    public BaseResponse<LocalLoginResponseDTO> loginLocalUser(LoginDTO loginDTO) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginDTO.getUsername(), loginDTO.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserAuthMethod userInfo = userAuthMethodRepository
                .findByUsernameAndAuthProvider(loginDTO.getUsername(), AuthProvider.LOCAL)
                .orElseThrow(() -> new InternalAuthenticationServiceException("Invalid username or password"));

        String token = tokenProvider.generateToken(
                userInfo.getUsername(),
                AuthProvider.LOCAL,
                userInfo.getUserId(),
                userInfo.getId()
        );
        String refreshToken = tokenProvider.generateRefreshToken(
                userInfo.getUsername(),
                AuthProvider.LOCAL,
                userInfo.getUserId(),
                userInfo.getId()
        );

        LocalLoginResponseDTO localLoginResponseDTO = new LocalLoginResponseDTO(userInfo.getUsername(), token, refreshToken);
        return new BaseResponse<>(HttpStatus.OK.value(), "Login successful", localLoginResponseDTO);
    }

    public BaseResponse<String> verifyEmail(AddLocalAuthenticationUserRequestDTO addLocalAuthenticationUserRequestDTO) {
        try {
            validate.validateRegistrationInput(addLocalAuthenticationUserRequestDTO);

            if (userAuthMethodRepository.existsByUsername(addLocalAuthenticationUserRequestDTO.getUsername())) {
                throw new CreatedLocalUserFailException(CommonString.USERNAME_IS_EXISTED);
            }

            if (userAuthMethodRepository.existsByAuthProviderAndEmail(AuthProvider.LOCAL, addLocalAuthenticationUserRequestDTO.getEmail())) {
                throw new CreatedLocalUserFailException(CommonString.EMAIL_IS_EXISTED);
            }

            sendVerificationEmail(addLocalAuthenticationUserRequestDTO);
            return new BaseResponse<>(HttpStatus.OK.value(), HttpStatus.OK.getReasonPhrase(), CommonString.SEND_MESSAGE_TO_EMAIL_SUCCESSFULLY);
        } catch (InputValidationException e) {
            return new BaseResponse<>(HttpStatus.BAD_REQUEST.value(), HttpStatus.BAD_REQUEST.getReasonPhrase(), e.getMessage());
        } catch (MessagingException e) {
            throw new CannotSendMessageException(CommonString.CAN_NOT_SEND_EMAIL);
        }
    }

    @Override
    @Transactional
    public AddLocalAuthenticationUserResponseDTO addUserAuthentication(String token) {
        try {
            AddLocalAuthenticationUserRequestDTO dataFromRedis = validate.verifyToken(CommonString.VERIFY_EMAIL_KEY_PREFIX + token, AddLocalAuthenticationUserRequestDTO.class);

            CreateUserTransferMessage transferMessage = CreateUserTransferMessage.builder()
                    .name(dataFromRedis.getName())
                    .email(dataFromRedis.getEmail())
                    .avatar(dataFromRedis.getAvatar())
                    .gender(dataFromRedis.getGender())
                    .phoneNumber(dataFromRedis.getPhoneNumber())
                    .dateOfBirth(dataFromRedis.getDateOfBirth())
                    .build();

            Long userId = (Long) rabbitTemplate.convertSendAndReceive(
                    "user.exchange",
                    "user.create",
                    transferMessage,
                    message -> {
                        message.getMessageProperties().setReplyTo("user.create.reply.queue"); // Reply Queue
                        return message;
                    }
            );

            if (userId == null) {
                throw new CreatedLocalUserFailException(CommonString.CAN_NOT_CREATE_NEW_USER);
            }

            UserAuthMethod userAuthMethod = new UserAuthMethod();
            userAuthMethod.setUserId(userId); // Sử dụng User ID từ User Service
            userAuthMethod.setRole(roleRepository.findByRoleName(RoleName.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Role not found")));
            userAuthMethod.setAuthProvider(AuthProvider.LOCAL);
            userAuthMethod.setEmail(dataFromRedis.getEmail());
            userAuthMethod.setUsername(dataFromRedis.getUsername());
            userAuthMethod.setPasswordHash(passwordEncoder.encode(dataFromRedis.getPasswordHash()));
            UserAuthMethod savedLocalAuthenticationUser = userAuthMethodRepository.saveAndFlush(userAuthMethod);

            return Mapper.mapEntityToDto(savedLocalAuthenticationUser, AddLocalAuthenticationUserResponseDTO.class);
        } catch (Exception e) {
            logger.error("Error occurred while adding user authentication: ", e);
            throw new CreatedLocalUserFailException(CommonString.CAN_NOT_CREATE_NEW_USER);
        }
    }

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
        ResetPasswordRequestDTO resetPasswordRequestDTO = validate.verifyToken(CommonString.VERIFY_EMAIL_KEY_PREFIX + token, ResetPasswordRequestDTO.class);

        validate.validateInputDataForResetPassword(resetPasswordDataDTO);

        UserAuthMethod userAuthMethod = userAuthMethodRepository.findByUsernameAndAuthProviderAndEmail(resetPasswordRequestDTO.getUsername(), AuthProvider.LOCAL, resetPasswordRequestDTO.getEmail())
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

    public BaseResponse<String> handleLoginSuccessByO2Auth(OAuth2User oAuth2User) {
        String providerUserId = oAuth2User.getAttribute("sub") != null ? oAuth2User.getAttribute("sub") : oAuth2User.getAttribute("id");
        UserAuthMethod userAuthMethod = userAuthMethodRepository.findByProviderUserIdAndAuthProvider(providerUserId, AuthProvider.GOOGLE).orElseThrow(() -> new OAuth2AuthenticationException(CommonString.CAN_NOT_LOGIN_BY_GOOGLE));
        String token = tokenProvider.generateToken(userAuthMethod.getUsername(), AuthProvider.GOOGLE, userAuthMethod.getUserId(), userAuthMethod.getId());
        return new BaseResponse<>(HttpStatus.OK.value(), CommonString.LOGIN_SUCCESSFULLY, token);
    }
}
