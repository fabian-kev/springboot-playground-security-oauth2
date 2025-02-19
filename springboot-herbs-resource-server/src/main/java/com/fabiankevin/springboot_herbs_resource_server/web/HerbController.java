package com.fabiankevin.springboot_herbs_resource_server.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/herbs")
public class HerbController {

    @GetMapping
    public List<HerbResponse> getHerbs() {
        return List.of(new HerbResponse("Stevia"),
                new HerbResponse("Mint")
        );
    }
}
