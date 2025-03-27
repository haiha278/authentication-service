package blog.collection.auth_service.service;

import blog.collection.auth_service.common.AuthProvider;
import blog.collection.auth_service.common.RoleName;
import blog.collection.auth_service.entity.User;
import blog.collection.auth_service.entity.UserAuthMethod;
import blog.collection.auth_service.repository.RoleRepository;
import blog.collection.auth_service.repository.UserAuthMethodRepository;
import blog.collection.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
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

    private final UserRepository userRepository;
    private final UserAuthMethodRepository userAuthMethodRepository;
    private final RoleRepository roleRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = new DefaultOAuth2UserService().loadUser(userRequest);
        String provider = userRequest.getClientRegistration().getRegistrationId();
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");
        String providerUserId = oAuth2User.getAttribute("sub") != null ? oAuth2User.getAttribute("sub") : oAuth2User.getAttribute("id");

        User user = createUserIfNotExisted(email, name, oAuth2User.getAttribute("picture"));

        createUserAuthMethodIfNotExisted(AuthProvider.valueOf(provider.toUpperCase()), user, providerUserId, email);

        return new DefaultOAuth2User(Collections.singletonList(new SimpleGrantedAuthority(RoleName.ROLE_USER.name())), oAuth2User.getAttributes(), "email");
    }

    private User createUserIfNotExisted(String email, String name, String avatar) {
        return userRepository.findByEmail(email).orElseGet(() -> {
            User newUser = new User();
            newUser.setEmail(email);
            newUser.setName(name);
            newUser.setAvatar(avatar);
            newUser.setStatus(true);
            newUser.setCreatedAt(java.time.LocalDateTime.now().toString());
            newUser.setUpdateAt(java.time.LocalDateTime.now().toString());
            return userRepository.save(newUser);
        });
    }

    private void createUserAuthMethodIfNotExisted(AuthProvider authProvider, User user, String providerUserId, String email) {
        userAuthMethodRepository.findByProviderUserIdAndAuthProvider(providerUserId, authProvider).orElseGet(() -> {
            UserAuthMethod newUserAuthMethod = new UserAuthMethod();
            newUserAuthMethod.setAuthProvider(authProvider);
            newUserAuthMethod.setRole(roleRepository.findByRoleName(RoleName.ROLE_USER).orElseThrow(() -> new RuntimeException("Role not found")));
            newUserAuthMethod.setUsername(email.split("@")[0]);
            newUserAuthMethod.setUser(user);
            newUserAuthMethod.setProviderUserId(providerUserId);
            return userAuthMethodRepository.save(newUserAuthMethod);
        });
    }
}
