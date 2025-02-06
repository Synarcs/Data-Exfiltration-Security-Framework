package com.synarcs.controller.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;

import com.synarcs.controller.protocols.DnsFeatures;
import com.synarcs.controller.repository.DNSBlacklistRepository;
import com.synarcs.controller.repository.MaliciousDomain;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class BlacklistDomain {
    
    @Autowired
    private DNSBlacklistRepository dnsBlacklistRepository;

    public List<MaliciousDomain> findAll() {
        return dnsBlacklistRepository.findAll();
    }

    public MaliciousDomain save(MaliciousDomain domain) {
        return dnsBlacklistRepository.save(domain);
    }

    public Optional<MaliciousDomain> findById(String sld) {
        return dnsBlacklistRepository.findById(sld);
    }

    @KafkaListener(topics = "exfil-sec", containerFactory = "maliciousDomainsListenerFactory")
    public void blacklistMaliciousDomains(DnsFeatures maliciousEvent) {
        if (!maliciousEvent.getTld().equals("") && !maliciousEvent.getFqdn().equals("")) {
            dnsBlacklistRepository.save(
                new MaliciousDomain(
                    maliciousEvent.getTld(),
                    maliciousEvent.getFqdn(),
                    false
                )
            );
        }
    }

    public void unBlockDomain(MaliciousDomain domain) {
        dnsBlacklistRepository.delete(domain);
    }
}
