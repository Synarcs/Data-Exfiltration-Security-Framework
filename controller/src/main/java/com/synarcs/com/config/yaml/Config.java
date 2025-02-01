package com.synarcs.com.config.yaml;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

// all custom config for the controller to process enhance stream analytics 

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Config {
    private Controller controller;
    private KafkaBrokerConfig streamConfig;
}
