package blog.collection.auth_service.service;

import blog.collection.auth_service.common.AuthProvider;
import blog.collection.auth_service.common.RoleName;
import blog.collection.auth_service.dto.tranferMessage.CreateUserTransferMessage;

import blog.collection.auth_service.entity.UserAuthMethod;
import blog.collection.auth_service.repository.RoleRepository;
import blog.collection.auth_service.repository.UserAuthMethodRepository;

import lombok.RequiredArgsConstructor;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class O2AuthServiceImpl implements OAuth2Service {

    private final UserAuthMethodRepository userAuthMethodRepository;
    private final RoleRepository roleRepository;
    private final RabbitTemplate rabbitTemplate;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = new DefaultOAuth2UserService().loadUser(userRequest);
        String provider = userRequest.getClientRegistration().getRegistrationId();
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");
        String providerUserId = oAuth2User.getAttribute("sub") != null ? oAuth2User.getAttribute("sub") : oAuth2User.getAttribute("id");
        String gender = oAuth2User.getAttribute("gender");

        Long userId = createUserIfNotExisted(email, name, oAuth2User.getAttribute("picture"), gender);

        createUserAuthMethodIfNotExisted(AuthProvider.valueOf(provider.toUpperCase()), userId, providerUserId, email);

        return new DefaultOAuth2User(Collections.singletonList(new SimpleGrantedAuthority(RoleName.ROLE_USER.name())), oAuth2User.getAttributes(), "email");
    }

    private Long createUserIfNotExisted(String email, String name, String avatar, String gender) {
        CreateUserTransferMessage transferMessage = new CreateUserTransferMessage();
        transferMessage.setName(name);
        transferMessage.setEmail(email);
        transferMessage.setAvatar(avatar);
        transferMessage.setGender(gender);

        return (Long) rabbitTemplate.convertSendAndReceive(
                "user.exchange",          // Exchange
                "user.create",
                transferMessage,
                message -> {
                    message.getMessageProperties().setReplyTo("user.create.reply.queue"); // Reply Queue
                    return message;
                }
        );
    }

    private void createUserAuthMethodIfNotExisted(AuthProvider authProvider, Long userId, String providerUserId, String email) {
        userAuthMethodRepository.findByProviderUserIdAndAuthProvider(providerUserId, authProvider).orElseGet(() -> {
            UserAuthMethod newUserAuthMethod = new UserAuthMethod();
            newUserAuthMethod.setAuthProvider(authProvider);
            newUserAuthMethod.setRole(roleRepository.findByRoleName(RoleName.ROLE_USER).orElseThrow(() -> new RuntimeException("Role not found")));
            newUserAuthMethod.setUsername(email.split("@")[0]);
            newUserAuthMethod.setUserId(userId);
            newUserAuthMethod.setProviderUserId(providerUserId);
            return userAuthMethodRepository.save(newUserAuthMethod);
        });
    }
}