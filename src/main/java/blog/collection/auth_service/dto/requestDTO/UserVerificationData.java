package blog.collection.auth_service.dto.requestDTO;

import blog.collection.auth_service.entity.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserVerificationData {
    private User user;
    private String username;
    private String password;
}
