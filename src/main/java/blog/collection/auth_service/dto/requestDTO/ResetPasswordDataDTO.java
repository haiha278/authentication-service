package blog.collection.auth_service.dto.requestDTO;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ResetPasswordDataDTO {
    private String newPassword;
    private String confirmNewPassword;
}
