package blog.collection.auth_service.dto.requestDTO;

import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Getter
@Setter
@Builder
public class LoginDTO {
    private String username;
    private String password;
}
