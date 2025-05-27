/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
*/

package com.synarcs.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 *  Main Kafka Stream Controller 
 *  Process Threat Streams forwarded and processed from kernel eBPF Node agent for threat detected events 
 */
@SpringBootApplication
public class App  {
    private static Logger logger = LoggerFactory.getLogger(App.class);
    
    public static void main(String[] args) {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Closing the controller for Data exfiltration security framework");
        }));

        SpringApplication.run(App.class);
    }

}
