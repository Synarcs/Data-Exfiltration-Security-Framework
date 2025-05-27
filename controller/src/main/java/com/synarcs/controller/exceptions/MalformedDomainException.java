/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
*/

package com.synarcs.controller.exceptions;


import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.ControllerAdvice;

import lombok.extern.slf4j.Slf4j;

@ControllerAdvice
@Service
@Slf4j
public class MalformedDomainException extends Exception {
    
   
    public MalformedDomainException() {
    }
 
    public MalformedDomainException(String message) {
       super(message);
    }
 
}
