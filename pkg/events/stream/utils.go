/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
*/

package stream

import (
	"fmt"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/conf"
)

type StreamBrokerConfig struct {
	Brokers            []string
	GlobalConfig       *conf.NodeAgentConfig
	NodeAgentCliConfig *conf.NodeAgentCliOptions
}

func InitBrokerConfig(globalConfig *conf.NodeAgentConfig, cliConfig *conf.NodeAgentCliOptions) *StreamBrokerConfig {
	return &StreamBrokerConfig{
		Brokers:            LoadKafkaBrokersConfig(globalConfig),
		GlobalConfig:       globalConfig,
		NodeAgentCliConfig: cliConfig,
	}
}

// TODO: Apply config creation pattern to load broker config with different input configuration
func LoadKafkaBrokersConfig(globalConfig *conf.NodeAgentConfig) []string {
	// TODO: Repalce with broker list for multi broker Kafka cluster for HA, and topic replication more than 1

	return []string{
		fmt.Sprintf("%s:%s", globalConfig.StreamServers.Ip, globalConfig.StreamServers.Port),
	}
}
