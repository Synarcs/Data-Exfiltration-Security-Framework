package com.synarcs.controller.service;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


import org.xbill.DNS.DClass;
import org.xbill.DNS.Type;

import com.synarcs.controller.config.yaml.Config;

import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Message;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Section;


@Service
public class MaliciousNsResolve {
    private final Logger logger = LoggerFactory.getLogger(MaliciousNsResolve.class);

    // used by control plane to add infer messgae in topic to instruct all nodes in data plane to blacklist them in cache and rehydrate cache, preventing reuse of unix socket for inference over ONNX  on node
    private final String internalRecursorerResolver = "10.158.82.55"; // use this since for test environment the server lookup for DNS over internal AUTH server 
    
    private Config controllerConfig;

    @Autowired
    public MaliciousNsResolve(Config config) {
        this.controllerConfig = config;
    }

    /*
     * Returns the l4 address for resolution of the malicious detected c2 domains for all data plane nodes to stop l4 traffic over it 
     * For the test build use powerdns recursor which internally forwards the query to upstream recursor forwarders, or internal organizational PowerDNS auth servers 
    */
    public List<String> getAddresses(String domain) {
        List<String> address = new ArrayList<>();

        try {
            Resolver r = new SimpleResolver(internalRecursorerResolver);
            
            // get the malicious IPv4 addresses 
            for (String record : lookupDNSRecords(domain + ".", Type.A, r)) 
                address.add(record);

            // get the malicious IPv6 addresses 
            for (String record : lookupDNSRecords(domain + ".", Type.AAAA, r)) 
                address.add(record);
            return address;
        }catch(Exception exception) {
            exception.printStackTrace();
            return address;
        }
    }

    private List<String> lookupDNSRecords(String domain, int type, Resolver resolver) {
        List<String> addressLookups = new ArrayList<>();

        try {
            Record queryRecord = Record.newRecord(Name.fromString(domain), type, DClass.IN);
            Message queryMessage = Message.newQuery(queryRecord);

            Message response = resolver.send(queryMessage);

            /*
             * The data plane only cares for the remote auth server responsible for C2 and not with additional which non-authorative servers adds during DNS lookups 
             */
            List<Record> answers = response.getSection(Section.ANSWER);
            if (answers.size() == 0) {
                logger.info("No records found for " + domain + " Type: " + Type.string(type));
            } else {
                for (Record record : answers) {
                    addressLookups.add(record.rdataToString());
                }
            }
            return addressLookups;
        } catch (Exception e) {
            e.printStackTrace();
            return addressLookups;
        }
    }
}
