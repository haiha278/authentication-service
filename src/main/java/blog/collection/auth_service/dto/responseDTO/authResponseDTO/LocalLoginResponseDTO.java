package blog.collection.auth_service.dto.responseDTO.authResponseDTO;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class LocalLoginResponseDTO {
    private String username;
    private String token;
    private String refreshToken;
}
