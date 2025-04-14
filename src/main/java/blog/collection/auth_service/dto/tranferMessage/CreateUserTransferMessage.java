package blog.collection.auth_service.dto.tranferMessage;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDate;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class CreateUserTransferMessage implements Serializable {
    private String name;
    private String email;
    private String phoneNumber;
    private String avatar; // URL sau khi upload
    private String gender;
    private LocalDate dateOfBirth;
    private byte[] avatarBytes;
    private String username;
    private String passwordHash;
}
