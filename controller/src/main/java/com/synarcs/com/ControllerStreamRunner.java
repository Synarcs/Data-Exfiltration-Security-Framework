package com.synarcs.com;

import java.io.Serializable;

public class ControllerStreamRunner implements Serializable, IController, Runnable {
    
    public ControllerStreamRunner() {
        super();
    }

    @Override 
    public void run() {}
    /**
     * Configure the remote kafka broker for stream analytics over the trheat events streamed by each node agent 
     */
    public void ConfigureKafkaBroker(String brokerUrl, int BrokerPort){
    }

    /**
     * Defines the complete Kafka streams DSL to process Kstream and Ktable for threat stream analytics.
     */
    public void ProcessStreamAnalyticsDSl(){
        
        Thread current = Thread.currentThread();
        System.out.println("processing the broker stream analytics for the thread " + current.getId() + 
                        current.getName());
    }
}
