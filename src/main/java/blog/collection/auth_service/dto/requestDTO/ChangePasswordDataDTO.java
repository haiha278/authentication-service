package blog.collection.auth_service.dto.requestDTO;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class ChangePasswordDataDTO {
    private String currentPassword;
    private String newPassword;
    private String confirmNewPassword;
}
