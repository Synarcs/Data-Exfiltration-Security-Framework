package utils

import "sync"

var global_cache_lock sync.Mutex

type DomainNodeAgentCacheBlock struct {
	TLD            string
	CompleteDomain string
}

// later implement the nodeagent service cachine layer on this
var NODE_AGENT_BLACKLISTED_DOMAINS map[string]DomainNodeAgentCacheBlock = make(map[string]DomainNodeAgentCacheBlock)

func UpdateDomainBlacklist(domain string, domainInfo DomainNodeAgentCacheBlock) {
	global_cache_lock.Lock()
	NODE_AGENT_BLACKLISTED_DOMAINS[domain] = domainInfo
	defer global_cache_lock.Unlock()
}
