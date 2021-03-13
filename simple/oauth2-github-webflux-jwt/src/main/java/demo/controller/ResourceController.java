package demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {
    // TODO: this does not work with JWT auth, try making it a separate resource server
    @PreAuthorize("hasAuthority('SCOPE_read:user')")
    @GetMapping("/resource")
    public String resource() {
        return "Allowed!";
    }
}
