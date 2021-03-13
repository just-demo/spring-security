package demo.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/secured")
public class SecuredController {

    @PreAuthorize("isAnonymous()")
    @GetMapping("/is/anonymous")
    public String anonymous() {
        return "Allowed!";
    }

    // TODO: why does nothing work here?
    @PreAuthorize("isAuthenticated()")
    @GetMapping("/is/authenticated")
    public String authenticated() {
        return "Allowed!";
    }

    @Secured("ROLE_USER")
    @GetMapping("/role/user")
    public String roleUser() {
        return "Allowed!";
    }

    @Secured("ROLE_DENIED")
    @GetMapping("/role/denied")
    public String roleDenied() {
        return "Allowed!";
    }
}
