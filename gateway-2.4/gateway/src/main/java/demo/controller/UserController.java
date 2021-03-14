package demo.controller;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

@RestController
public class UserController {
    @GetMapping("/")
    public Mono<OAuth2AuthorizedClient> user(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient client) {
        return Mono.just(client);
    }

    @GetMapping("/session")
    public Mono<WebSession> session(WebSession session) {
        return Mono.just(session);
    }
}
