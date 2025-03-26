package blog.collection.auth_service.dto.responseDTO.authResponseDTO;

import lombok.*;

import java.time.LocalDateTime;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class ChangePasswordResponseDTO {
    private Long id;
    private LocalDateTime updateAt;
}
