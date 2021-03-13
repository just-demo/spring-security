package demo.config;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.RedirectServerLogoutSuccessHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static com.nimbusds.jose.JOSEObjectType.JWT;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static java.util.UUID.randomUUID;
import static java.util.stream.Collectors.toList;
import static net.minidev.json.JSONObject.toJSONString;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfiguration {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http,
            ServerAuthenticationSuccessHandler authenticationSuccessHandler,
            ServerLogoutSuccessHandler logoutSuccessHandler,
            ReactiveJwtDecoder jwtDecoder,
            ReactiveJwtAuthenticationConverterAdapter jwtAuthenticationConverter
    ) {
        return http
                .authorizeExchange(authorizeExchange -> authorizeExchange
                        .pathMatchers("/").permitAll()
                        .anyExchange().authenticated())
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(new HttpStatusServerEntryPoint(UNAUTHORIZED))
                        // TODO: why doesn't it work?
                        .accessDeniedHandler(new HttpStatusServerAccessDeniedHandler(FORBIDDEN)))
                .oauth2Login(login -> login.authenticationSuccessHandler(authenticationSuccessHandler))
                .logout(logout -> logout.logoutSuccessHandler(logoutSuccessHandler))
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(jwt -> jwt
                        .jwtDecoder(jwtDecoder)
                        .jwtAuthenticationConverter(jwtAuthenticationConverter)))
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .build();
    }

    @Bean
    public ReactiveJwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
        return NimbusReactiveJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
    }

    @Bean
    public RSAKey rsaKey() throws JOSEException {
        return new RSAKeyGenerator(2048).generate();
    }

    @Bean
    public ServerAuthenticationSuccessHandler authenticationSuccessHandler(RSAKey rsaKey) {
        return (exchange, authentication) -> {
            ServerHttpResponse response = exchange.getExchange().getResponse();
            String token = buildJwtToken(authentication, rsaKey);
            byte[] body = toJSONString(singletonMap("token", token)).getBytes(UTF_8);
            response.getHeaders().put(CONTENT_TYPE, singletonList(APPLICATION_JSON_VALUE));
            // TODO: how to return token and redirect to "/" at the same time?
            return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
        };
    }

    @Bean
    public ServerLogoutSuccessHandler logoutSuccessHandler() {
        RedirectServerLogoutSuccessHandler handler = new RedirectServerLogoutSuccessHandler();
        handler.setLogoutSuccessUrl(URI.create("/")); // default is /login?logout
        return handler;
    }

    /**
     * Overrides default to prevent adding "SCOPE_" prefix since it is already added by third party
     * auth provider (i.e. github) whenever needed
     */
    @Bean
    public ReactiveJwtAuthenticationConverterAdapter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthorityPrefix("");
        JwtAuthenticationConverter authenticationConverter = new JwtAuthenticationConverter();
        authenticationConverter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return new ReactiveJwtAuthenticationConverterAdapter(authenticationConverter);
    }


    private String buildJwtToken(Authentication authentication, RSAKey rsaKey) {
        try {
            JWSSigner signer = new RSASSASigner(rsaKey.toPrivateKey());
            JWSHeader header = new JWSHeader.Builder(RS256).type(JWT).build();
            List<String> scope = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(toList());
            Payload payload = new Payload(new JWTClaimsSet.Builder()
                    .expirationTime(Date.from(Instant.now().plus(Duration.ofMinutes(60))))
                    .jwtID(randomUUID().toString())
                    .claim("scope", scope)
                    .build()
                    .toJSONObject());
            JWSObject jws = new JWSObject(header, payload);
            jws.sign(signer);
            return jws.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }
}
