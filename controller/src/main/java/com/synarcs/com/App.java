package com.synarcs.com;

import java.io.Serializable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 *  Main Kafka Stream Controller 
 *  Process Threat Streams forwarded and processed from kernel eBPF Node agent for threat detected events 
 */
public class App implements Serializable {
    private static final int MAX_LOCKS = 10;
    private static final CountDownLatch lockThreads = new CountDownLatch(MAX_LOCKS);

    public static void main( String[] args ){

        ExecutorService service = Executors.newFixedThreadPool(1 << 5);
        for (int i=0; i < (1 << 5); i++) service.submit(new ControllerStreamRunner());

        try {
            lockThreads.await();
        }catch (InterruptedException exception) {
            exception.printStackTrace();
        }

        Runtime.getRuntime().addShutdownHook(
            new Thread(() -> {
                service.shutdown();
                System.out.println("Clossing the kafka stream controller with result close ...");
            })
        );
    }   
}
