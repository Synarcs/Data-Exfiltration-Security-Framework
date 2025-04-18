package com.synarcs.controller;

import java.io.Serializable;
import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.synarcs.controller.protocols.ProtocolEnums;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

public class NodeCache<T> implements Serializable {

    private final Cache<String, Boolean> cache;
    private final int MAX_MAL_BLACK_DOM_CT = 10_000;

    // init cache for performance with lru cache eviction to reduce unwanted blacklisting calls to the recursor interceprors on the DNS server
    public NodeCache() {
        cache = Caffeine
            .newBuilder()
            .maximumSize(MAX_MAL_BLACK_DOM_CT)
            .expireAfterWrite(Duration.ofDays(1))
            .executor(Runnable::run)
            .recordStats()
            .build();
    }

    // preserve ordering for insertion 
    private final Map<T, Integer> ct = new LinkedHashMap<>();

    // all the kmaps can be converted to shared scache space for different nodes 
    // domain ipv4 / ipv6 --> Map<String, Integer>>  (sld domain, count  (exfiltrated attempts detected on node (malware retry)))
    private final Map<T, Map<T, Integer>> nodeSldExfilCount = new HashMap<>();
    private final Map<T, Map<ProtocolEnums, Integer>> nodeProtocolExfilCount = new HashMap<>();
    
    
    Logger log = LoggerFactory.getLogger(NodeCache.class);

    public void addRecordInCache(T sld) {
        this.ct.put(sld, this.ct.getOrDefault(sld,  0) + 1);
    }

    public void addSldCountPerNode(T sld, T nodeIp) {
        this.nodeSldExfilCount.computeIfAbsent(nodeIp, 
                k ->  new HashMap<T, Integer>()).put(sld, 
                    this.nodeSldExfilCount.get(nodeIp).getOrDefault(sld, 0 ) + 1);
    }

    public void addExfilProtocolCountPerNode(ProtocolEnums protocol, T nodeIp) {
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