/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package xdp

import (
	"context"
	"strconv"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/conf"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events/stream"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/model"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/progs"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/rpc/inference"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
)

func (ing *IngressSniffHandler) IngressRemoteInferHandler(ctx context.Context, features [][]float32, rawFeatures []model.DNSFeatures,
	iface *netinet.NetIface, streamClient *stream.StreamProducer, InferenceServerSock *inference.DNSOnnxInferenceService) error {
	// process deep lexical analysis from remote unix transport inference server

	inferenceResponse, err := ing.InferenceServerSock.IngressInference(ctx, features)
	if err != nil {
		utils.Logger.Error(err)
		return nil
	}

	for index, resp := range inferenceResponse.ThreatType {
		if resp {
			utils.IngUpdateDomainBlacklistInCache(rawFeatures[index].Tld)
			// putting here 53 the standard DNS port since the socket transport from kernel must be detected before handle itself no need to again check
			// the same port as used for egrres will be used as src port for response from remote c2c malware
			go events.ExportMaliciousEvents[progs.Protocol](events.DNSFeatures(rawFeatures[index]),
				&iface.PhysicalNodeBridgeIpv4, events.DNS, int(utils.DNS_EGRESS_PORT), nil)

			if !conf.GlobalAgentCliConfig.DisableThreadEventStream {
				go streamClient.MarshallStreamThreadEvent(ctx, rawFeatures[index], stream.HostNetworkExfilFeatures{
					ExfilPort:        strconv.Itoa(int(utils.DNS_EGRESS_PORT)),
					Protocol:         string(events.DNS),
					PhysicalNodeIpv4: iface.PhysicalNodeBridgeIpv4.String(),
					PhysicalNodeIpv6: iface.PhysicalNodeBridgeIpv6.String(),
				})
			}
		} else {
			utils.UpdateDomainNestedEgressCache(rawFeatures[index].Tld, rawFeatures[index].Fqdn, false)
		}
	}
	return nil
}
