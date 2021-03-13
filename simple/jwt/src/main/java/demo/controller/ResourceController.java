package demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class ResourceController {

    @GetMapping
    public String home() {
        return "Allowed!";
    }

    @GetMapping("/jwt")
    public Jwt user(@AuthenticationPrincipal Jwt jwt) {
        return jwt;
    }

    // TODO: why does @AuthenticationPrincipal make the argument null in 2.4.3 unlike 2.3.9
    @GetMapping("/principal")
    public Principal principal(Principal principal) {
        return principal;
    }

    @PreAuthorize("hasAuthority('SCOPE_user')")
    // @PreAuthorize("#oauth2.hasScope('user')") // this does not seem to work
    @GetMapping("/user")
    public String user() {
        return "Allowed!";
    }
}
