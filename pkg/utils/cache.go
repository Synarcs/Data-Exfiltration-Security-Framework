package utils

import (
	"log"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
)

/*
	Implement an multi heriachial cache with each key in lru cache holding information about the tld
	The value for each heirachiel cache is a list of domains which are blacklisted as a struct field
*/

var global_cache_lock sync.Mutex

type DomainNodeAgentCacheBlock struct {
	CompleteDomain map[string]bool
}

// later implement the nodeagent service cachine layer on this
var NODE_AGENT_BLACKLISTED_DOMAINS *lru.Cache[string, DomainNodeAgentCacheBlock]

func InitCache() error {
	log.Println("Init the Lru Cache for the Node Agent")
	cache, err := lru.New[string, DomainNodeAgentCacheBlock](MAX_NODE_AGENT_CACHE_SIZE)
	if err != nil {
		log.Println("Error creating the Lru caceh", err)
		return err
	}
	NODE_AGENT_BLACKLISTED_DOMAINS = cache
	return nil
}

// tld and the value
func UpdateDomainBlacklistInCache(tld, completeDomain string) {
	global_cache_lock.Lock()
	log.Println("Adding Malicious Domain in the Cache", tld)
	var evict bool
	fdCache, fd := NODE_AGENT_BLACKLISTED_DOMAINS.Get(tld)
	if !fd {
		evict = NODE_AGENT_BLACKLISTED_DOMAINS.Add(tld, DomainNodeAgentCacheBlock{
			CompleteDomain: map[string]bool{
				completeDomain: true,
			},
		})
	} else {
		_, fd := fdCache.CompleteDomain[completeDomain]
		if !fd {
			fdCache.CompleteDomain[completeDomain] = true
		}
		evict = NODE_AGENT_BLACKLISTED_DOMAINS.Add(tld, fdCache)
	}

	if evict && DEBUG {
		log.Println("Cache Hit the max Size evicted the Least Recently Used Key")
	}

	defer global_cache_lock.Unlock()
}

func DeleteDomainBlackListInCache(tld, domain string) {
	global_cache_lock.Lock()
	var evict bool
	_, fd := NODE_AGENT_BLACKLISTED_DOMAINS.Get(tld)
	if !fd {
		log.Fatalf("The Domain is not in the Cache Cannot evict the cache %s", tld)
	} else {
		value, _ := NODE_AGENT_BLACKLISTED_DOMAINS.Get(tld)
		delete(value.CompleteDomain, domain)
		if len(value.CompleteDomain) == 0 {
			NODE_AGENT_BLACKLISTED_DOMAINS.Remove(tld)
		} else {
			evict = NODE_AGENT_BLACKLISTED_DOMAINS.Add(tld, value)
		}
	}

	if evict && DEBUG {
		log.Println("Cache Hit the max Size evicted the Least Recently Used Key")
	}

	defer global_cache_lock.Unlock()
}
