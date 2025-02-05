package com.synarcs.com.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.synarcs.com.repository.MaliciousDomain;
import com.synarcs.com.service.BlacklistDomain;

import lombok.extern.slf4j.Slf4j;

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

    @PostMapping("/malicious/{sld}")
    public String addMaliciousDomain(@RequestParam("sld") String sld) {
        return sld;
    }

}
