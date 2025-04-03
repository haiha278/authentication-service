package blog.collection.auth_service.repository;

import blog.collection.auth_service.common.AuthProvider;
import blog.collection.auth_service.entity.UserAuthMethod;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserAuthMethodRepository extends JpaRepository<UserAuthMethod, Long> {
    Optional<UserAuthMethod> findByUsernameAndAuthProvider(String username, AuthProvider authProvider);

    boolean existsByUsername(String username);

    Optional<UserAuthMethod> findByProviderUserIdAndAuthProvider(String providerUserId, AuthProvider authProvider);

    boolean existsByAuthProviderAndEmail(AuthProvider authProvider, String email);

    boolean existsByUsernameAndEmail(String username, String email);

    Optional<UserAuthMethod> findByUsernameAndAuthProviderAndEmail(String username, AuthProvider authProvider, String email);
}
