package com.synarcs.controller.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

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

    @Autowired
    private DNSBlacklistRepository dnsBlacklistRepository;

    @Autowired
    private KafkaTemplate<String, DnsdataplaneBlk> kafkaTemplate;

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
            sendDNSCacheAddDataplane(maliciousEvent);
        }
    }


    public void sendDNSCacheAddDataplane(DnsFeatures maliciousEvent) {
        kafkaTemplate.send(controllerInferenceTopic, DnsdataplaneBlk.builder().
                fqdn(maliciousEvent.getFqdn())
                .tld(maliciousEvent.getTld())
                .recordType(maliciousEvent.getRecordType())
                .isForcedUnBlocked(false)
                .detectedThreadNodeIpv4(maliciousEvent.getPhysicalNodeIpv4())
                .detectedThreadNodeIpv6(maliciousEvent.getPhysicalNodeIpv6())
                .build());
    }

    public void unBlockDomain(MaliciousDomain domain) {
        dnsBlacklistRepository.delete(domain);
    }
}
