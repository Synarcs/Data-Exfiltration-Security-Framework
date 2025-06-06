/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package conf

import pb "github.com/Synarcs/Data-Exfiltration-Security-Framework/exfil_sec_api"

// only extreact what the controller unix cni netpool handler needs from root controller
type GlobalControllerConfig struct {
	StreamConfig struct {
		Host                               string `json:"host"`
		BrokerPort                         int    `json:"brokerPort"`
		StreamThreatTopic                  string `json:"streamThreatTopic"`
		StreamThreatTopicInferState        string `json:"streamThreatTopicInferState"`
		RecursorTCPTransportMaliciousTopic string `json:"recursorTCPTransportMaliciousTopic"`
		ConsumerGroupName                  string `json:"consumerGroupName"`
	} `json:"streamConfig"`
	K8sCniConfig struct {
		K8sAdvertisedHostServiceAddress string `json:"k8sAdvertisedHostServiceAddress"`
		Cni                             struct {
			Name string `json:"name"`
		} `json:"cni"`
	} `json:"k8s"`
}

func TestHandler() {
	var _ pb.UnimplementedNodeAgentCryptoServiceServer

}
