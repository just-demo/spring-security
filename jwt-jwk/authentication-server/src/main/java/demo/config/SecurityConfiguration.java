package demo.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SecurityConfiguration {
    @Bean
    public RSAKey rsaKey() throws JOSEException {
        return new RSAKeyGenerator(2048).generate();
    }
}
