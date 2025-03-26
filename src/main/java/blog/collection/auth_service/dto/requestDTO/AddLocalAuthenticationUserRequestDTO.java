package blog.collection.auth_service.dto.requestDTO;

import blog.collection.auth_service.entity.Role;
import blog.collection.auth_service.entity.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AddLocalAuthenticationUserRequestDTO {
    private String name;
    private String email;
    private String phoneNumber;
    private String avatar;
    private String username;
    private String passwordHash;
}
