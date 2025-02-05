package com.synarcs.com;

import java.io.Serializable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.sun.tools.javac.Main;

/**
 *  Main Kafka Stream Controller 
 *  Process Threat Streams forwarded and processed from kernel eBPF Node agent for threat detected events 
 */
@SpringBootApplication
public class App {
    public static final int MAX_LOCKS = 10;
    private static final CountDownLatch lockThreads = new CountDownLatch(1);
    private final Lock lock = new ReentrantLock();

    
    public static void main(String[] args) {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Closing the controller for Data exfiltration security framework");
            lockThreads.countDown();
        }));

        SpringApplication.run(App.class);
    }
}
