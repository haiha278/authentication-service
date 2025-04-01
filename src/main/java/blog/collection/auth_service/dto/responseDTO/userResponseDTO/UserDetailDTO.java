package blog.collection.auth_service.dto.responseDTO.userResponseDTO;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class UserDetailDTO {
    private Long id;
    private String name;
    private String email;
    private String phoneNumber;
    private String avatar;
}
