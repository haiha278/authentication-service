package blog.collection.auth_service.dto.requestDTO;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AddLocalAuthenticationUserRequestDTO {

    private String name;

    private String email;

    private String phoneNumber;

    private String gender;

    private LocalDate dateOfBirth;

    private String username;

    private String passwordHash;
}
