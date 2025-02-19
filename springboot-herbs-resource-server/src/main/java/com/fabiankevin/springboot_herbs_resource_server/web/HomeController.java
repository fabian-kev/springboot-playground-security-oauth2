package com.fabiankevin.springboot_herbs_resource_server.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/home")
public class HomeController {

    @GetMapping
    public String home() {
        return "<h1>Hello!</h1>";
    }
}
