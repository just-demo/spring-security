package demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class ResourceController {

    @GetMapping
    public String home() {
        return "Allowed!";
    }

    @GetMapping("/principal")
    public Principal principal(@AuthenticationPrincipal Principal principal) {
        return principal;
    }

    @PreAuthorize("hasRole('ROLE_USER')")
    @GetMapping("/user")
    public String user() {
        return "Allowed!";
    }

    @PreAuthorize("hasRole('ROLE_DENIED')")
    @GetMapping("/denied")
    public String denied() {
        return "Denied!";
    }
}