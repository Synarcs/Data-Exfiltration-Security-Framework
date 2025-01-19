package com.synarcs.com.cache;

import java.io.Serializable;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;

import com.synarcs.com.powerdns.RecursorBlackList;
import com.synarcs.com.protocols.IFeatureTransportProtocol;
import com.synarcs.com.protocols.ProtocolEnums;

public class NodeCache<T> implements Serializable {

    // post local caching use the powerdns recursor to apply preresolve interceptors to start blocking from this domains 
    private RecursorBlackList<T> recursorBlackList;

    // preserve ordering for insertion 
    private Map<T, Integer> ct = new LinkedHashMap<>();

    // all the kmaps can be converted to shared scache space for different nodes 
    // domain ipv4 / ipv6 --> Map<String, Integer>>  (sld domain, count  (exfiltrated attempts detected on node (malware retry)))
    private Map<T, Map<T, Integer>> nodeSldExfilCount = new HashMap<>();
    private Map<T, Map<ProtocolEnums, Integer>> nodeProtocolExfilCount = new HashMap<>();
    
    Logger log = LoggerFactory.getLogger(NodeCache.class);

    public NodeCache() {
        this.recursorBlackList = new RecursorBlackList<T>();
    }

    public void addRecordInCache(T sld) {
        if (!this.ct.containsKey(sld)) {
            this.recursorBlackList.blacklistDomain(sld);
        }
        this.ct.put(sld, this.ct.getOrDefault(sld,  0) + 1);
    }

    public void addSldCountPerNode(T sld, T nodeIp) {
        log.info("Adding the egress exfil node ipv4 address to nodeSldExfilCount controller cache :: " + sld + " " + nodeIp.toString());
        this.nodeSldExfilCount.computeIfAbsent(nodeIp, 
                k ->  new HashMap<T, Integer>()).put(sld, 
                    this.nodeSldExfilCount.get(nodeIp).getOrDefault(sld, 0 ) + 1);
    }

    public void addExfilProtocolCountPerNode(ProtocolEnums protocol, T nodeIp) {
        log.info("Adding the egress exfil node ipv4 address to nodeProtocolExfilCount controller cache :: " + nodeIp.toString());
        this.nodeProtocolExfilCount.computeIfAbsent(nodeIp, 
            k ->  new HashMap<ProtocolEnums, Integer>()).put(protocol, 
                    this.nodeProtocolExfilCount.get(nodeIp).getOrDefault(protocol, 0 ) + 1);
    } 

    public void readRecords() {
        log.info("the SLD cache for all nodes in data plane ::");
        for (T record : this.ct.keySet()) {
            System.out.println("Node cache Record: " + record.toString());
        }
        log.info("the SLD cache for all nodes each node in  plane ::");
        for (T record : this.nodeSldExfilCount.keySet()) {
            System.out.println("Node cache Record: " + record.toString());
        }
        log.info("the SLD cache for all nodes each node in  plane by protocol ::");
        for (T record : this.nodeProtocolExfilCount.keySet()) {
            System.out.println("Node cache Record: " + record.toString());
        }
    }
}