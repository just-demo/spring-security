package demo.controller;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class KeyController {
    @Autowired
    private RSAKey rsaKey;

    /**
     * Exposes jwkSetUri endpoint to be used by resource sever
     */
    @GetMapping("/keys")
    public JSONObject keys() {
        // The result includes public key only
        return new JWKSet(rsaKey).toJSONObject();
    }
}
