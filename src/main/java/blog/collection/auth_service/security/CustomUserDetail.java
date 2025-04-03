

package blog.collection.auth_service.security;

import blog.collection.auth_service.entity.UserAuthMethod;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Data
@AllArgsConstructor
public class CustomUserDetail implements UserDetails {
    private UserAuthMethod userAuthMethod;
    private Collection<? extends GrantedAuthority> authorities;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return userAuthMethod.getPasswordHash();
    }

    @Override
    public String getUsername() {
        return userAuthMethod.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public static CustomUserDetail mapToCustomUserDetail(UserAuthMethod userAuthMethod) {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(userAuthMethod.getRole().getRoleName().name());
        grantedAuthorities.add(simpleGrantedAuthority);
        return new CustomUserDetail(userAuthMethod, grantedAuthorities);
    }
}

