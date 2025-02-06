package com.synarcs.controller.config.yaml;


import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SchemaRegistryConfig {
    private int port;
    private String host;
}