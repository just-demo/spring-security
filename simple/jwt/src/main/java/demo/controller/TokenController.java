package demo.controller;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static com.nimbusds.jose.JOSEObjectType.JWT;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static java.util.UUID.randomUUID;

@RestController
public class TokenController {
    @Autowired
    private RSAKey rsaKey;

    @GetMapping("/token")
    public Map<String, String> token() throws Exception {
        JWSSigner signer = new RSASSASigner(rsaKey.toPrivateKey());

        JWSHeader header = new JWSHeader.Builder(RS256)
                .type(JWT)
                .build();

        Payload payload = new Payload(new JWTClaimsSet.Builder()
                .expirationTime(Date.from(Instant.now().plus(Duration.ofMinutes(60))))
                .jwtID(randomUUID().toString())
                // "roles" do not seem to have any effect unless JwtGrantedAuthoritiesConverter is overridden
                .claim("roles", singletonList("USER"))
                .claim("scope", singletonList("user"))
                .build()
                .toJSONObject());

        JWSObject jws = new JWSObject(header, payload);
        jws.sign(signer);
        return singletonMap("token", jws.serialize());
    }

    /**
     * An example of manual token verification
     */
    private boolean verify(String token) throws Exception {
        JWSVerifier verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());
        return JWSObject.parse(token).verify(verifier);
    }
}
