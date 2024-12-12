package com.synarcs.com;

import java.io.Serializable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Main Kafka Stream Controller 
 *
 */
public class App implements Serializable {
    public static void main( String[] args ){

        ExecutorService service = Executors.newFixedThreadPool(1 << 5);
        for (int i=0; i < (1 << 5); i++) service.submit(new ControllerStreamRunner());

        Runtime.getRuntime().addShutdownHook(
            new Thread(() -> {
                service.shutdown();
                System.out.println("Clossing the kafka stream controller with result close ...");
            })
        );
    }   
}
