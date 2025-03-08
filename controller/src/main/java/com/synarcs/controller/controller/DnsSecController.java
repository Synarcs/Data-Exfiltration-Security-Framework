package com.synarcs.controller.controller;

import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.synarcs.controller.repository.MaliciousDomain;
import com.synarcs.controller.service.BlacklistDomain;
import com.synarcs.controller.service.MaliciousNsResolve;


// later fix and move all business logic inside the dedicated blacklist service 

@RestController
public class DnsSecController implements Serializable {

    private Logger logger = LoggerFactory.getLogger(DnsSecController.class);

    @Autowired
    private BlacklistDomain dnsBlockMaliciousDomainService;

    @Autowired 
    private MaliciousNsResolve dnsResolver; 
    
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

    /*
     * Returns the resovled L3 RR, with overlay upstream DNS resolver to detect and provide all the upstream Node L3 Ip's runnsing the remote C2 Implant malware process 
     * The eBPF node agent has already reprogrammed data plane and kernel eBPF node agent to kill all such dns traffic from such ip addresses
     */
    @ResponseStatus(HttpStatus.OK) 
    @GetMapping("/c2/serverIp")
    public Map<String, List<String>> getAllPreventedRemoteC2ImplantServers() {
        logger.info("Fetching all the C2 Servers L3 Information Blacklisted by control plane , and reporgammed the data plane");
        Map<String, List<String>> c2ServersIps = new HashMap<>();
        
        List<MaliciousDomain> blkC2Domains = dnsBlockMaliciousDomainService.findAll();

        blkC2Domains.forEach(domain -> {
            c2ServersIps.put(domain.getSLD(), dnsResolver.getAddresses(domain.getSLD()));
        });
        
        return c2ServersIps;
    }


    @GetMapping("/c2/serverIp/{c2}")
    public MaliciousDomain getPreventedRemoteC2ImplantServerByDomain(@PathVariable String c2) {
        logger.info("Fetching the C2 Server L3 Information Blacklisted by control plane , and reporgammed the data plane" +  " " + c2);

        Optional<MaliciousDomain> c2DomainServer = dnsBlockMaliciousDomainService.findById(c2);
        if (c2DomainServer.isPresent()) {
            return c2DomainServer.get();
        }
        return null;
    }

}
