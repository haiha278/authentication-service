package blog.collection.auth_service.security;

import blog.collection.auth_service.common.AuthProvider;
import blog.collection.auth_service.common.CommonString;
import blog.collection.auth_service.entity.UserAuthMethod;
import blog.collection.auth_service.repository.UserAuthMethodRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@Component
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {
    private final UserAuthMethodRepository userAuthMethodRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<UserAuthMethod> optionalUserAuthMethod = userAuthMethodRepository.findByUsernameAndAuthProvider(username, AuthProvider.LOCAL);
        if (optionalUserAuthMethod.isPresent()) {
            return CustomUserDetail.mapToCustomUserDetail(optionalUserAuthMethod.get());
        } else {
            throw new blog.collection.auth_service.exception.UsernameNotFoundException(CommonString.USERNAME_NOT_FOUND);
        }
    }
}
