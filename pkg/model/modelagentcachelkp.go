/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package model

import "github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"

/*
to prevent reinference all the domains, including the TLD, and actual domain must be found in the cache of benign domain for faster inferenceing
*/
func StaticRuntimeBenignDomainChecks(features []DNSFeatures) bool {
	for _, feature := range features {
		if !utils.GetKeyPresentInEgressBenignRemoteInferCache(feature.Tld, feature.Fqdn) {
			return false
		}
	}
	return true
}

func StaticRuntimeMaliciousDomainChecks(features []DNSFeatures) bool {
	for _, dnsFeature := range features {
		if utils.GetKeyPresentInEgressCache(dnsFeature.Tld) {
			// consider malicious if any section of DNS packet contains this malicious domain TLD and already blacklisted in egress cache
			return true
		}
		if utils.IngDeleteDomainBlackListInCache(dnsFeature.Tld) {
			// if found in ingress cache as the tld should be blacklisted and dropped
			return true
		}
	}
	return false
}
