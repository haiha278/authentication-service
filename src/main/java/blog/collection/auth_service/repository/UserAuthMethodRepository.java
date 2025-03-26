package blog.collection.auth_service.repository;

import blog.collection.auth_service.common.AuthProvider;
import blog.collection.auth_service.entity.User;
import blog.collection.auth_service.entity.UserAuthMethod;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserAuthMethodRepository extends JpaRepository<UserAuthMethod, Long> {
    Optional<UserAuthMethod> findByUsernameAndAuthProvider(String username, AuthProvider authProvider);

    boolean existsByUsername(String username);

    Optional<UserAuthMethod> findByProviderUserIdAndAuthProvider(String providerUserId, AuthProvider authProvider);

    Optional<UserAuthMethod> findByUser(User user);

    boolean existsByAuthProviderAndUser(AuthProvider authProvider, User user);

    boolean existsByUsernameAndUserEmail(String username, String email);

    Optional<UserAuthMethod> findByUsernameAndAuthProviderAndUserEmail(String username, AuthProvider authProvider, String email);
}
