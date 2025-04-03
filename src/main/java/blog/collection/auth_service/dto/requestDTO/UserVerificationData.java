package blog.collection.auth_service.dto.requestDTO;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserVerificationData {
    private String name;
    private String email;
    private String phoneNumber;
    private String avatar;
    private String gender;
    private LocalDate dateOfBirth;
    private String username;
    private String password;
}
