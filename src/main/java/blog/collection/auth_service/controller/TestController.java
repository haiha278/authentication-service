package blog.collection.auth_service.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {
    @GetMapping("/auth/protected")
    public String protectedEndpoint() {
        return "Protected endpoint accessed";
    }
}
