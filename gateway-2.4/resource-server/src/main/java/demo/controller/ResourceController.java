package demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {
    @GetMapping("/")
    public String allowed() {
        return "Allowed!";
    }

    @PreAuthorize("hasAuthority('SCOPE_denied')")
    @GetMapping("/denied")
    public String denied() {
        return "Denied!";
    }

    @PreAuthorize("hasAuthority('SCOPE_user')")
    @GetMapping("/user")
    public Authentication user(Authentication authentication) {
        return authentication;
    }
}
