package com.fabiankevin.springboot_oaut2_login_and_client.web;

import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

@RestController
@RequestMapping("/v1/users")
public class UserController {

    @GetMapping
    public Map<String, String> getUserInfo(Principal principal) {
        return Map.of("name", principal.getName());
    }
}
