package com.synarcs.controller;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 *  Main Kafka Stream Controller 
 *  Process Threat Streams forwarded and processed from kernel eBPF Node agent for threat detected events 
 */
@SpringBootApplication
public class App {
    
    public static void main(String[] args) {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Closing the controller for Data exfiltration security framework");
        }));

        SpringApplication.run(App.class);
    }
}
