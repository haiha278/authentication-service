package blog.collection.auth_service.dto.responseDTO.authResponseDTO;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class AddUserResponseDTO {
    private Long userId;
    private LocalDateTime dateTimeCreated;
}
