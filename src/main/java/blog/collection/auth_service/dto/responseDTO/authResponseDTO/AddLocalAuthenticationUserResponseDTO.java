package blog.collection.auth_service.dto.responseDTO.authResponseDTO;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AddLocalAuthenticationUserResponseDTO {
    private Long id;
    private String createdAt;
}
