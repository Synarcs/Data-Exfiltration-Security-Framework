package utils

import (
	lru "github.com/hashicorp/golang-lru/v2"
)

/*
	Implement an multi heriachial cache with each key in lru cache holding information about the tld
	The value for each heirachiel cache is a list of domains which are blacklisted as a struct field
*/

type DomainNodeAgentCacheBlock struct {
	CompleteDomain map[string]bool
}

const INFERENED_DOMAIN_CACHE_SIZE_PER_TLD = 1000

// later implement the nodeagent service cachine layer on this
var NODE_AGENT_BLACKLISTED_DOMAINS *lru.Cache[string, *lru.Cache[string, bool]]
var NODE_AGENT_INGRESS_BACKLISTED_DOMAINS *lru.Cache[string, bool]

// Init the cache for the eBPF node agent in user space
func InitCache() error {
	Logger.Info("Init the Lru Cache for the Node Agent")
	cache, err := lru.New[string, *lru.Cache[string, bool]](MAX_NODE_AGENT_CACHE_SIZE)
	if err != nil {
		Logger.Info("Error creating the Lru cache for egress", err)
		return err
	}
	NODE_AGENT_BLACKLISTED_DOMAINS = cache
	// init the init ingress cache
	ingressCache, err := lru.New[string, bool](MAX_NODE_AGENT_CACHE_SIZE)
	if err != nil {
		Logger.Info("Error creating the Lru cache for ingress", err)
		return err
	}
	NODE_AGENT_INGRESS_BACKLISTED_DOMAINS = ingressCache

	return nil
}

// Egress cache processing for the eBPF node-agent LRU cache
// tld and the value
func UpdateDomainBlacklistInEgressCache(tld, fqdn string) {
	Logger.Info("Adding Malicious Domain in the Cache", tld)
	fdCache, fd := NODE_AGENT_BLACKLISTED_DOMAINS.Get(tld)
	if !fd {
		newDomainCache, err := lru.New[string, bool](INFERENED_DOMAIN_CACHE_SIZE_PER_TLD)
		if err != nil {
			Logger.Info("Error creating the inner LRU cache for tld", err, tld)
		}
		newDomainCache.Add(fqdn, true)
		NODE_AGENT_BLACKLISTED_DOMAINS.Add(tld, newDomainCache)
	} else {
		fdCache.Add(fqdn, true)
	}
}

// Get the tld from the egress cache
func GetKeyPresentInEgressCache(tld string) bool {
	_, fd := NODE_AGENT_BLACKLISTED_DOMAINS.Get(tld)
	return fd
}

// Delete the tld and fqdn from the egress cache
func DeleteDomainBlackListInEgressCache(tld, fqdn string) error {
	_, fd := NODE_AGENT_BLACKLISTED_DOMAINS.Get(tld)
	if !fd {
		Logger.Printf("The Required domain %s Cannot be blaclisted since its not there in cahce ", tld)
	} else {
		value, _ := NODE_AGENT_BLACKLISTED_DOMAINS.Get(tld)
		if fqdn == "" {
			Logger.Info("Removing a specific fqdn domain from node blacklist cache")
			NODE_AGENT_BLACKLISTED_DOMAINS.Remove(tld)
		} else {
			value.Remove(fqdn)
		}
	}

	return nil
}

func DeleteAllBlacklistforSLDInEgressCache(tld string) {
	NODE_AGENT_BLACKLISTED_DOMAINS.Remove(tld) // remove all the fqdn detected malicious on the specific node in the node agent cache
}

// Get the blacklisted domains from the  egress cache
func GetBlaclistedDomainsEgressCache() []string {
	Logger.Info("Inoveked CLI via Unix socket to runtiime inspect the required blaclisted SLD in the Node Agent LRU cache")

	returnBlacklistedDomains := []string{}
	returnBlacklistedDomains = append(returnBlacklistedDomains, NODE_AGENT_BLACKLISTED_DOMAINS.Keys()...)
	return returnBlacklistedDomains
}

// Ingress cache processing for the eBPF node-agent LRU cache
// Add the tld to the ingress cache
func IngUpdateDomainBlacklistInCache(tld string) {
	NODE_AGENT_INGRESS_BACKLISTED_DOMAINS.Add(tld, true)
}

// Check if the tld is present in the ingress cache and return value if present
func IngGetKeyPresentInCache(tld string) bool {
	_, fd := NODE_AGENT_INGRESS_BACKLISTED_DOMAINS.Get(tld)
	return fd
}

// Delete the tld from the ingress cache
func IngDeleteDomainBlackListInCache(tld string) bool {
	return NODE_AGENT_INGRESS_BACKLISTED_DOMAINS.Remove(tld)
}

// Get the list of tld present in the ingress cache
func GetBlaclistedDomainsIngressCache() []string {
	Logger.Info("Inoveked CLI via Unix socket to runtiime inspect the required blaclisted SLD in the Node Agent LRU cache")
	returnBlacklistedDomains := []string{}

	returnBlacklistedDomains = append(returnBlacklistedDomains, NODE_AGENT_INGRESS_BACKLISTED_DOMAINS.Keys()...)
	return returnBlacklistedDomains
}
