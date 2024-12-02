package com.synarcs.com;

import java.io.Serializable;

/**
 * Hello world!
 *
 */
public class App  implements Serializable {
    public static void main( String[] args ){
        
        Runnable childRunner = new ControllerStreamRunner();
    }   
}
