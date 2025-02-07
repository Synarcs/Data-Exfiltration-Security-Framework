package com.synarcs.controller.controller;

import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.synarcs.controller.repository.MaliciousDomain;
import com.synarcs.controller.service.BlacklistDomain;

import lombok.extern.slf4j.Slf4j;

// later fix and move all business logic inside the dedicated blacklist service 

@RestController
@RequestMapping("/")
public class DnsSecController {

    private Logger logger = LoggerFactory.getLogger(DnsSecController.class);

    @Autowired
    private BlacklistDomain dnsBlockMaliciousDomainService;
    
    @GetMapping
    public String getControllerVersion() {
        return "0.1.1";
    }

    @GetMapping("/malicious")
    public List<MaliciousDomain> getallMaliciousDomains() {
        return dnsBlockMaliciousDomainService.findAll();
    }

    @GetMapping("/malicious/{sld}")
    public Optional<MaliciousDomain> getMaliciousDomainBuSLD(@PathVariable String sld) {
        return dnsBlockMaliciousDomainService.findById(sld);
    }

    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping
    public MaliciousDomain addMaliciousDomain(@RequestBody MaliciousDomain domain) {
        return dnsBlockMaliciousDomainService.save(domain);
    }

    @ResponseStatus(HttpStatus.OK) 
    @GetMapping("/health") 
    public ResponseEntity<String> getControllerhealth() {
        return ResponseEntity
            .status(HttpStatusCode.valueOf(500))
            .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_PLAIN_VALUE)
            .body("UP");
    }

    @ResponseStatus(HttpStatus.OK) 
    @DeleteMapping("/unblock/{sld}")
    public void unblockMaliciousDomain(@PathVariable String sld) {
        Optional<MaliciousDomain> domain = dnsBlockMaliciousDomainService.findById(sld);
        if (domain.isPresent()) {
            logger.info("Unblocking domain: ", domain.get().getSLD() + " " + domain.get().getSLD());
            dnsBlockMaliciousDomainService.unBlockDomain(domain.get());
        }
    }
}
