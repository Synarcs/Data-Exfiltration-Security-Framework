package utils

import (
	lru "github.com/hashicorp/golang-lru/v2"
)

/*
	Core caching layer of the eBPF agent in userspace
	Implement an multi heriachial cache with each key in lru cache holding information about the tld
	The value for each heirachiel cache is a list of domains which are blacklisted as a struct field
*/

type DomainNodeAgentCacheBlock struct {
	CompleteDomain map[string]bool
}

// all the LRU caches for eBPF agent in userspace, must reside in the agent userspace heap memory
// apart from the eBPF maps in the kernel prceossing packet payload over kernel datapath, the userspace caches accelerate inference and per packet processing speed
var NODE_AGENT_BLACKLISTED_DOMAINS *lru.Cache[string, *lru.Cache[string, bool]]
var NODE_AGENT_INGRESS_BACKLISTED_DOMAINS *lru.Cache[string, bool]
var NODE_AGENT_REMOTE_INFERENCE_READ_THROUGH_CACHE *lru.Cache[string, *lru.Cache[string, bool]] // the SLD send for remote inference --> actual fqdn inferred result, must always contain benign domains sent and cached for lookup, considering malicious domain are stored in malicious cache

// Init the cache for the eBPF node agent in user space
func InitCache() error {
	Log("Init the Lru Cache for the Node Agent")
	cache, err := lru.New[string, *lru.Cache[string, bool]](MAX_NODE_AGENT_CACHE_SIZE)
	if err != nil {
		Log("Error creating the Lru cache for egress", err)
		return err
	}
	NODE_AGENT_BLACKLISTED_DOMAINS = cache
	// init the init ingress cache
	ingressCache, err := lru.New[string, bool](MAX_NODE_AGENT_CACHE_SIZE)
	if err != nil {
		Log("Error creating the Lru cache for ingress", err)
		return err
	}
	NODE_AGENT_INGRESS_BACKLISTED_DOMAINS = ingressCache

	benignLookThroughcache, err := lru.New[string, *lru.Cache[string, bool]](MAX_NODE_AGENT_CACHE_LOOKUP_SIZE)
	if err != nil {
		Log("Error creating read through cache for benign remote inferencing")
		return err
	}
	NODE_AGENT_REMOTE_INFERENCE_READ_THROUGH_CACHE = benignLookThroughcache

	return nil
}

// Egress cache processing for the eBPF node-agent LRU cache
// tld and the value
func UpdateDomainNestedEgressCache(tld, fqdn string, isBlackListEgress bool) {
	if isBlackListEgress {
		Log("Adding Malicious Domain in the Cache", tld)
		fdCache, fd := NODE_AGENT_BLACKLISTED_DOMAINS.Get(tld)
		if !fd {
			newDomainCache, err := lru.New[string, bool](INFERENED_DOMAIN_CACHE_SIZE_PER_TLD)
			if err != nil {
				Log("Error creating the inner LRU cache for tld for malicious domain cache", err, tld)
				return
			}
			newDomainCache.Add(fqdn, true)
			NODE_AGENT_BLACKLISTED_DOMAINS.Add(tld, newDomainCache)
		} else {
			fdCache.Add(fqdn, true)
		}
	} else {
		if DEBUG {
			Log("Adding Benign Inferred Domain in the Cache with associated fqdn used for inference", tld)
		}
		benginInternalinferdomainCache, fd := NODE_AGENT_REMOTE_INFERENCE_READ_THROUGH_CACHE.Get(tld)
		if !fd {
			newDomainCache, err := lru.New[string, bool](INFERENED_DOMAIN_CACHE_SIZE_PER_TLD)
			if err != nil {
				Log("Error creating the inner LRU cache for tld", err, tld)
				return
			}
			newDomainCache.Add(fqdn, true)
			NODE_AGENT_REMOTE_INFERENCE_READ_THROUGH_CACHE.Add(tld, newDomainCache)
		} else {
			benginInternalinferdomainCache.Add(fqdn, true)
		}
	}
}

// Get the tld from the egress cache
func GetKeyPresentInEgressCache(tld string) bool {
	_, fd := NODE_AGENT_BLACKLISTED_DOMAINS.Get(tld)
	return fd
}

func GetKeyPresentInEgressBenignRemoteInferCache(tld, fqdn string) bool {
	innerCache, fd := NODE_AGENT_REMOTE_INFERENCE_READ_THROUGH_CACHE.Get(tld)
	if !fd {
		return fd
	}

	_, fqdnFound := innerCache.Get(fqdn)
	if !fqdnFound {
		return fqdnFound
	}
	return true
}

// Delete the tld and fqdn from the egress cache
func DeleteDomainBlackListInEgressCache(tld, fqdn string) error {
	_, fd := NODE_AGENT_BLACKLISTED_DOMAINS.Get(tld)
	if !fd {
		Logger.Printf("The Required domain %s Cannot be blaclisted since its not there in cahce ", tld)
	} else {
		value, _ := NODE_AGENT_BLACKLISTED_DOMAINS.Get(tld)
		if fqdn == "" {
			Log("Removing a specific fqdn domain from node blacklist cache")
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
	Log("Inoveked CLI via Unix socket to runtiime inspect the required blaclisted SLD in the Node Agent LRU cache")

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
	Log("Inoveked CLI via Unix socket to runtiime inspect the required blaclisted SLD in the Node Agent LRU cache")
	returnBlacklistedDomains := []string{}

	returnBlacklistedDomains = append(returnBlacklistedDomains, NODE_AGENT_INGRESS_BACKLISTED_DOMAINS.Keys()...)
	return returnBlacklistedDomains
}
