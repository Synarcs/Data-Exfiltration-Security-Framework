/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package com.synarcs.controller.exceptions;


import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import lombok.extern.slf4j.Slf4j;

@ControllerAdvice
@Service
@Slf4j
public class GenericException {
    
    // add custom controller exception for processing 
    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> returnControllerError(Exception exception) {
        return ResponseEntity
            .status(HttpStatusCode.valueOf(500))
            .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_PLAIN_VALUE)
            .body(exception.getMessage());
    }

    @ExceptionHandler(MalformedDomainException.class)
    public ResponseEntity<String> returnMalformedDomainRequestError(MalformedDomainException exception) {
        return ResponseEntity
            .status(HttpStatusCode.valueOf(500))
            .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_PLAIN_VALUE)
            .body(exception.getMessage());
    }
}
