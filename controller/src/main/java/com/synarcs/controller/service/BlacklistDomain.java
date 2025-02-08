package com.synarcs.controller.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import com.synarcs.controller.config.yaml.Config;
import com.synarcs.controller.repository.DNSBlacklistRepository;
import com.synarcs.controller.repository.MaliciousDomain;
import com.synarcs.controller.streamserdes.DnsFeatures;
import com.synarcs.controller.streamserdes.DnsdataplaneBlk;

import lombok.extern.slf4j.Slf4j;


@Service
@Slf4j
public class BlacklistDomain {

    // used by control plane to add infer messgae in topic to instruct all nodes in data plane to blacklist them in cache and rehydrate cache, preventing reuse of unix socket for inference over ONNX  on node
    private final String controllerInferenceTopic = "exfil-sec-infer-controller";
    private final String internalRecursorerResolver = "10.158.82.55"; // use this since for test environment the server lookup for DNS over internal AUTH server 

    private Config controllerConfig;

    @Autowired
    private DNSBlacklistRepository dnsBlacklistRepository;


    @Autowired
    private MaliciousNsResolve dnsResolver;

    @Autowired
    private KafkaTemplate<String, DnsdataplaneBlk> kafkaTemplate;


    @Autowired
    public BlacklistDomain(Config config) {
        this.controllerConfig = config;
    }

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
            sendDNSCacheAddDataplane(maliciousEvent, 
                    dnsResolver.getAddresses(maliciousEvent.getTld()));
        }
    }


    public void sendDNSCacheAddDataplane(DnsFeatures maliciousEvent, List<String> resolveAddressMaliciousC2Domains) {
        kafkaTemplate.send(controllerInferenceTopic, DnsdataplaneBlk.builder().
                fqdn(maliciousEvent.getFqdn())
                .tld(maliciousEvent.getTld())
                .recordType(maliciousEvent.getRecordType())
                .isForcedUnBlocked(false)
                .detectedThreadNodeIpv4(maliciousEvent.getPhysicalNodeIpv4())
                .detectedThreadNodeIpv6(maliciousEvent.getPhysicalNodeIpv6())
                .resolveAddressMaliciousC2Domains(resolveAddressMaliciousC2Domains)
                .build());
    }

    public void unBlockDomain(MaliciousDomain domain) {
        dnsBlacklistRepository.delete(domain);
    }


  
}
