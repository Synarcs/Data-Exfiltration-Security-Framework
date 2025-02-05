package com.synarcs.com.controller;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.synarcs.com.repository.MaliciousDomain;
import com.synarcs.com.service.BlacklistDomain;

import lombok.extern.slf4j.Slf4j;

// later fix and move all business logic inside the dedicated blacklist service 

@RestController
@RequestMapping("/")
@Slf4j
public class DnsSecController {

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

}
