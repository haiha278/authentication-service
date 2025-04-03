package blog.collection.auth_service.dto.tranferMessage;

import lombok.Builder;
import lombok.Data;

import java.io.Serializable;
import java.time.LocalDate;

@Builder
@Data
public class CreateUserTransferMessage implements Serializable {
    private String name;
    private String email;
    private String phoneNumber;
    private String avatar;
    private String gender;
    private LocalDate dateOfBirth;
}
