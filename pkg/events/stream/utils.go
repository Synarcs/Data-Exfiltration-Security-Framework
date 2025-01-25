package stream

import (
	"fmt"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
)

type StreamBrokerConfig struct {
	Brokers      []string
	GlobalConfig *utils.NodeAgentConfig
}

func InitBrokerConfig(globalConfig *utils.NodeAgentConfig) *StreamBrokerConfig {
	return &StreamBrokerConfig{
		Brokers:      LoadKafkaBrokersConfig(globalConfig),
		GlobalConfig: globalConfig,
	}
}

// TODO: Apply config creation pattern to load broker config with different input configuration
func LoadKafkaBrokersConfig(globalConfig *utils.NodeAgentConfig) []string {
	// TODO: Repalce with broker list for multi broker Kafka cluster for HA, and topic replication more than 1

	return []string{
		fmt.Sprintf("%s:%s", globalConfig.StreamServers.Ip, globalConfig.StreamServers.Port),
	}
}
