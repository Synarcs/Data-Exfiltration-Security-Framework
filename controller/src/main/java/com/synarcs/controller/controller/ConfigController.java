package com.synarcs.controller.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.synarcs.controller.config.yaml.Config;

import lombok.extern.slf4j.Slf4j;

@RestController
@Slf4j
public class ConfigController {
    private Config config; 
    
    @Autowired
    public ConfigController(Config config) {
        this.config = config;
    }

    @GetMapping("/config")
    public Config getControllerBootedConfig() {
        return this.config;
    }
    
}
