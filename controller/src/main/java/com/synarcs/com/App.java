package com.synarcs.com;

import java.io.Serializable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 *  Main Kafka Stream Controller 
 *  Process Threat Streams forwarded and processed from kernel eBPF Node agent for threat detected events 
 */
public class App implements Serializable {
    private static final int MAX_LOCKS = 10;
    private static final CountDownLatch lockThreads = new CountDownLatch(1);
    private final Lock lock = new ReentrantLock();

    
    public static void main(String[] args) {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Closing the kafka stream controller...");
            lockThreads.countDown();
        }));

        try {
            new Thread(new ControllerStreamRunner()).start();
            lockThreads.await();
        } catch (InterruptedException exception) {
            System.out.println("Current Root Thread Interrupted");
            Thread.currentThread().interrupt();
        }
    }
}
