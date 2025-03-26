package blog.collection.auth_service.dto.requestDTO;

import lombok.*;

@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class ResetPasswordRequestDTO {
    private String email;
    private String username;
}
