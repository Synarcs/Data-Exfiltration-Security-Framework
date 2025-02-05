package com.synarcs.com.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.synarcs.com.repository.DNSBlacklistRepository;
import com.synarcs.com.repository.MaliciousDomain;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class BlacklistDomain {
    
    @Autowired
    public DNSBlacklistRepository dnsBlacklistRepository;

    public List<MaliciousDomain> findAll() {
        return dnsBlacklistRepository.findAll();
    }
}
