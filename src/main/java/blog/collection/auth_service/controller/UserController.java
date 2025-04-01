package blog.collection.auth_service.controller;

import blog.collection.auth_service.dto.responseDTO.commonResponse.BaseResponse;
import blog.collection.auth_service.dto.responseDTO.userResponseDTO.UserDetailDTO;
import blog.collection.auth_service.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/blog-collection/auth")
@CrossOrigin("*")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @PostMapping("/user")
    public ResponseEntity<BaseResponse<UserDetailDTO>> personalInfo(@RequestHeader("X-UserId") String userId) {
        return new ResponseEntity<>(userService.userDetailInfo(userId), HttpStatus.OK);
    }
}
