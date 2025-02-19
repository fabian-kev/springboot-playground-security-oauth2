package com.fabiankevin.springboot_oaut2_login_and_client.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping
public class HomeController {

    @GetMapping("/")
    public String home(){
        return "<h1>Hello!</h1>";
    }
}
