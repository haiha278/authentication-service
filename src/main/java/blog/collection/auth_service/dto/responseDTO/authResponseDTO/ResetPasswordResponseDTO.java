package blog.collection.auth_service.dto.responseDTO.authResponseDTO;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Builder
@Getter
@Setter
public class ResetPasswordResponseDTO {
    private LocalDateTime updateAt;
    private Long userId;
}
