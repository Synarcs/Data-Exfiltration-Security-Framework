package utils

import (
	"log"

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

func InitCache() error {
	log.Println("Init the Lru Cache for the Node Agent")
	cache, err := lru.New[string, *lru.Cache[string, bool]](MAX_NODE_AGENT_CACHE_SIZE)
	if err != nil {
		log.Println("Error creating the Lru cache for egress", err)
		return err
	}
	NODE_AGENT_BLACKLISTED_DOMAINS = cache
	// init the init ingress cache
	ingressCache, err := lru.New[string, bool](MAX_NODE_AGENT_CACHE_SIZE)
	if err != nil {
		log.Println("Error creating the Lru cache for ingress", err)
		return err
	}
	NODE_AGENT_INGRESS_BACKLISTED_DOMAINS = ingressCache

	return nil
}

// tld and the value
func UpdateDomainBlacklistInCache(tld, fqdn string) {
	log.Println("Adding Malicious Domain in the Cache", tld)
	var evict bool
	fdCache, fd := NODE_AGENT_BLACKLISTED_DOMAINS.Get(tld)
	if !fd {
		newDomainCache, err := lru.New[string, bool](INFERENED_DOMAIN_CACHE_SIZE_PER_TLD)
		if err != nil {
			log.Println("Error creating the inner LRU cache for tld", err, tld)
		}
		newDomainCache.Add(fqdn, true)
		evict = NODE_AGENT_BLACKLISTED_DOMAINS.Add(tld, newDomainCache)
	} else {
		fdCache.Add(fqdn, true)
	}

	if evict && DEBUG {
		log.Println("Cache Hit the max Size evicted the Least Recently Used Key")
	}

}

// add support for generics with go base type inferences
func IngUpdateDomainBlacklistInCache(tld, fqdn string) {
	isEvict := NODE_AGENT_INGRESS_BACKLISTED_DOMAINS.Add(tld, true)
	if isEvict && DEBUG {
		log.Println("The Node cache for ingress becaome almost full evict cache process ...")
	}
}

func GetKeyPresentInCache(tld string) bool {
	_, fd := NODE_AGENT_BLACKLISTED_DOMAINS.Get(tld)
	return fd
}

func IngGetKeyPresentInCache(tld string) bool {
	_, fd := NODE_AGENT_INGRESS_BACKLISTED_DOMAINS.Get(tld)
	return fd
}

func DeleteDomainBlackListInCache(tld, fqdn string) {
	var evict bool
	_, fd := NODE_AGENT_BLACKLISTED_DOMAINS.Get(tld)
	if !fd {
		log.Fatalf("The Domain is not in the Cache Cannot evict the cache %s", tld)
	} else {
		value, _ := NODE_AGENT_BLACKLISTED_DOMAINS.Get(tld)
		value.Remove(fqdn)
	}

	if evict && DEBUG {
		log.Println("Cache Hit the max Size evicted the Least Recently Used Key")
	}

}

func IngDeleteDomainBlackListInCache(tld string) bool {
	return NODE_AGENT_INGRESS_BACKLISTED_DOMAINS.Remove(tld)
}
