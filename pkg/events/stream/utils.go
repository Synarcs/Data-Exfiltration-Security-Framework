package stream

import (
	"fmt"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
)

type StreamBrokerConfig struct {
	Brokers      []string
	GlobalConfig *utils.NodeAgentConfig
}

// TODO: Apply config creation pattern to load broker config with different input configuration
func (config *StreamBrokerConfig) LoadKafkaBrokersConfig() {
	// TODO: Repalce with broker list for multi broker Kafka cluster for HA, and topic replication more than 1
	brokerAddress := fmt.Sprintf("%s:%s", config.GlobalConfig.StreamServer.Ip, config.GlobalConfig.StreamServer.Port)

	config.Brokers = []string{
		brokerAddress,
	}
}
