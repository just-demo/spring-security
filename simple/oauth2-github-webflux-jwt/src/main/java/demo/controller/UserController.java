package demo.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class UserController {
    @GetMapping("/user")
    public OAuth2User user(@AuthenticationPrincipal OAuth2User user) {
        return user;
    }

    @GetMapping("/jwt")
    public Jwt jwt(@AuthenticationPrincipal Jwt jwt) {
        return jwt;
    }

    @GetMapping("/principal")
    public Principal principal(@AuthenticationPrincipal Principal principal) {
        return principal;
    }
}
