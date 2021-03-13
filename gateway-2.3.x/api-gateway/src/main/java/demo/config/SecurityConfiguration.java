package demo.config;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.security.oauth2.gateway.TokenRelayGatewayFilterFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.RedirectServerLogoutSuccessHandler;
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler;

import java.net.URI;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfiguration {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .authorizeExchange(authorizeExchange -> authorizeExchange
                        .pathMatchers("/").permitAll()
                        .anyExchange().authenticated())
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(new HttpStatusServerEntryPoint(UNAUTHORIZED))
                        // TODO: why doesn't it work?
                        .accessDeniedHandler(new HttpStatusServerAccessDeniedHandler(FORBIDDEN)))
                .oauth2Login(login -> login.authenticationSuccessHandler(new RedirectServerAuthenticationSuccessHandler("/"))) // default is protected page previously visited
                .logout(logout -> logout.logoutSuccessHandler(createLogoutHandler("/"))) // default is /login?logout
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .build();
    }

    /**
     * Alternatively this could be applied per each route as
     * .filters(f -> f.filter(filterFactory.apply()))
     */
    @Bean
    public GlobalFilter tokenRelayFilter(TokenRelayGatewayFilterFactory filterFactory) {
        return (exchange, chain) -> filterFactory.apply().filter(exchange, chain);
    }

    private RedirectServerLogoutSuccessHandler createLogoutHandler(String location) {
        RedirectServerLogoutSuccessHandler handler = new RedirectServerLogoutSuccessHandler();
        handler.setLogoutSuccessUrl(URI.create(location));
        return handler;
    }
}
