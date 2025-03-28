package blog.collection.auth_service.service;

import blog.collection.auth_service.common.AuthProvider;
import blog.collection.auth_service.common.CommonString;
import blog.collection.auth_service.common.RoleName;
import blog.collection.auth_service.dto.requestDTO.AddLocalAuthenticationUserRequestDTO;
import blog.collection.auth_service.dto.requestDTO.LoginDTO;
import blog.collection.auth_service.dto.requestDTO.UserVerificationData;
import blog.collection.auth_service.dto.responseDTO.authResponseDTO.AddLocalAuthenticationUserResponseDTO;
import blog.collection.auth_service.dto.responseDTO.authResponseDTO.LocalLoginResponseDTO;
import blog.collection.auth_service.dto.responseDTO.commonResponse.BaseResponse;
import blog.collection.auth_service.entity.User;
import blog.collection.auth_service.entity.UserAuthMethod;
import blog.collection.auth_service.exception.CannotSendMessageException;
import blog.collection.auth_service.exception.CreatedLocalUserFailException;
import blog.collection.auth_service.exception.InputValidationException;
import blog.collection.auth_service.exception.UsernameNotFoundException;
import blog.collection.auth_service.mapper.Mapper;
import blog.collection.auth_service.repository.RoleRepository;
import blog.collection.auth_service.repository.UserAuthMethodRepository;
import blog.collection.auth_service.repository.UserRepository;
import blog.collection.auth_service.security.CustomUserDetail;
import blog.collection.auth_service.security.JwtTokenProvider;
import blog.collection.auth_service.utils.EmailUtils;
import blog.collection.auth_service.utils.Validate;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Optional;


@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationServiceImpl implements AuthenticationService {
    private final UserRepository userRepository;
    private final UserAuthMethodRepository userAuthMethodRepository;
    private final RoleRepository roleRepository;
    private final EmailUtils emailUtils;
    private final Validate validate;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    private final AuthenticationManager authenticationManager;
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationServiceImpl.class);

    private void sendVerificationEmail(User user, String username, String password) throws MessagingException {
        emailUtils.sendToVerifyEmail(user, username, password);
    }

    public BaseResponse<LocalLoginResponseDTO> loginLocalUser(LoginDTO loginDTO) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginDTO.getUsername(), loginDTO.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        CustomUserDetail customUserDetail = (CustomUserDetail) authentication.getPrincipal();
        UserAuthMethod userInfo = userAuthMethodRepository
                .findByUsernameAndAuthProvider(loginDTO.getUsername(), AuthProvider.LOCAL)
                .orElseThrow(() -> new UsernameNotFoundException(CommonString.USERNAME_NOT_FOUND));

        String token = tokenProvider.generateToken(
                userInfo.getUsername(),
                AuthProvider.LOCAL,
                userInfo.getUser().getId(),
                userInfo.getId()
        );
        String refreshToken = tokenProvider.generateRefreshToken(
                userInfo.getUsername(),
                AuthProvider.LOCAL,
                userInfo.getUser().getId(),
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

            String userEmail = addLocalAuthenticationUserRequestDTO.getEmail();
            if (userRepository.existsByEmail(userEmail)) {
                if (userAuthMethodRepository.existsByAuthProviderAndUser(AuthProvider.LOCAL, userRepository.findByEmail(userEmail).get())) {
                    throw new CreatedLocalUserFailException(CommonString.EMAIL_IS_EXISTED);
                }
            }

            User user = Mapper.mapDtoToEntity(addLocalAuthenticationUserRequestDTO, User.class);
            sendVerificationEmail(user, addLocalAuthenticationUserRequestDTO.getUsername(), addLocalAuthenticationUserRequestDTO.getPasswordHash());
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
            UserVerificationData data = validate.verifyToken(token, UserVerificationData.class);
            User inputUserFromRedis = data.getUser(); // Đây là user từ phía client (chưa có id)
            System.out.println("data:" + inputUserFromRedis);
            // 1. Tìm user theo email
            User user;
            Optional<User> existingUserOpt = userRepository.findByEmail(inputUserFromRedis.getEmail());

            if (existingUserOpt.isPresent()) {
                user = existingUserOpt.get();
            } else {
                inputUserFromRedis.setStatus(true);
                user = userRepository.save(inputUserFromRedis); // Lúc này user có id
            }
            if (!userAuthMethodRepository.existsByAuthProviderAndUser(AuthProvider.LOCAL, user)) {
                UserAuthMethod userAuthMethod = new UserAuthMethod();
                userAuthMethod.setUser(user);
                userAuthMethod.setRole(roleRepository.findByRoleName(RoleName.ROLE_USER)
                        .orElseThrow(() -> new RuntimeException("Role not found")));
                userAuthMethod.setAuthProvider(AuthProvider.LOCAL);
                userAuthMethod.setUsername(data.getUsername());
                userAuthMethod.setPasswordHash(passwordEncoder.encode(data.getPassword()));
                UserAuthMethod savedLocalAuthenticationUser = userAuthMethodRepository.saveAndFlush(userAuthMethod);
                return Mapper.mapEntityToDto(savedLocalAuthenticationUser, AddLocalAuthenticationUserResponseDTO.class);
            }
            return null;
        } catch (Exception e) {
            logger.error("Error occurred while adding user authentication: ", e);
            throw new CreatedLocalUserFailException(CommonString.CAN_NOT_CREATE_NEW_USER);
        }
    }

//    @Override
//    @Transactional
//    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
//        OAuth2User oAuth2User = new DefaultOAuth2UserService().loadUser(userRequest);
//        String provider = userRequest.getClientRegistration().getRegistrationId();
//        String email = oAuth2User.getAttribute("email");
//        String name = oAuth2User.getAttribute("name");
//        String providerUserId = oAuth2User.getAttribute("sub") != null ? oAuth2User.getAttribute("sub") : oAuth2User.getAttribute("id");
//
//        User user = createUserIfNotExisted(email, name, oAuth2User.getAttribute("picture"));
//
//        createUserAuthMethodIfNotExisted(AuthProvider.valueOf(provider.toUpperCase()), user, providerUserId, email);
//
//        return new DefaultOAuth2User(Collections.singletonList(new SimpleGrantedAuthority(RoleName.ROLE_USER.name())), oAuth2User.getAttributes(), "email");
//    }
//
//    private User createUserIfNotExisted(String email, String name, String avatar) {
//        return userRepository.findByEmail(email).orElseGet(() -> {
//            User newUser = new User();
//            newUser.setEmail(email);
//            newUser.setName(name);
//            newUser.setAvatar(avatar);
//            newUser.setStatus(true);
//            newUser.setCreatedAt(java.time.LocalDateTime.now().toString());
//            newUser.setUpdateAt(java.time.LocalDateTime.now().toString());
//            return userRepository.save(newUser);
//        });
//    }
//
//    private void createUserAuthMethodIfNotExisted(AuthProvider authProvider, User user, String providerUserId, String email) {
//        userAuthMethodRepository.findByProviderUserIdAndAuthProvider(providerUserId, authProvider).orElseGet(() -> {
//            UserAuthMethod newUserAuthMethod = new UserAuthMethod();
//            newUserAuthMethod.setAuthProvider(authProvider);
//            newUserAuthMethod.setRole(roleRepository.findByRoleName(RoleName.ROLE_USER).orElseThrow(() -> new RuntimeException("Role not found")));
//            newUserAuthMethod.setUsername(email.split("@")[0]);
//            newUserAuthMethod.setUser(user);
//            newUserAuthMethod.setProviderUserId(providerUserId);
//            return userAuthMethodRepository.save(newUserAuthMethod);
//        });
//    }

    public BaseResponse<String> handleLoginSuccessByO2Auth(OAuth2User oAuth2User) {
        String providerUserId = oAuth2User.getAttribute("sub") != null ? oAuth2User.getAttribute("sub") : oAuth2User.getAttribute("id");
        UserAuthMethod userAuthMethod = userAuthMethodRepository.findByProviderUserIdAndAuthProvider(providerUserId, AuthProvider.GOOGLE).orElseThrow(() -> new OAuth2AuthenticationException(CommonString.CAN_NOT_LOGIN_BY_GOOGLE));
        String token = tokenProvider.generateToken(userAuthMethod.getUsername(), AuthProvider.GOOGLE, userAuthMethod.getUser().getId(), userAuthMethod.getId());
        return new BaseResponse<>(HttpStatus.OK.value(), CommonString.LOGIN_SUCCESSFULLY, token);
    }
}
