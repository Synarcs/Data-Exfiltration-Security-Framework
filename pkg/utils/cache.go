package utils

import (
	"log"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
)

var global_cache_lock sync.Mutex

type DomainNodeAgentCacheBlock struct {
	TLD            string
	CompleteDomain string
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

func UpdateDomainBlacklistInCache(domain string, domainInfo DomainNodeAgentCacheBlock) {
	global_cache_lock.Lock()
	log.Println("Adding Malicious Domain in the Cache", domain)
	evict := NODE_AGENT_BLACKLISTED_DOMAINS.Add(domain, domainInfo)

	if evict {
		log.Println("Cache Hit the max Size evicted the Least Recently Used Key")
	}

	go StreamThreatEvent[DomainNodeAgentCacheBlock](&domainInfo)
	defer global_cache_lock.Unlock()
}

func DeleteDomainBlackListInCache(domain string) {
	global_cache_lock.Lock()
	NODE_AGENT_BLACKLISTED_DOMAINS.Remove(domain)
	defer global_cache_lock.Unlock()
}

func StreamThreatEvent[T comparable](eventInfo *DomainNodeAgentCacheBlock) error {
	log.Println("Streaming the Threat event for malicious found domain", eventInfo)
	return nil
}