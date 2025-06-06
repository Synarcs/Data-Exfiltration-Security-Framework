/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package conf

import (
	"errors"
	"os"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"gopkg.in/yaml.v2"
)

// cli agent config for booting the node agent at the endpoitn
var (
	GlobalAgentCliConfig *NodeAgentCliOptions
)

type (
	NodeAgentCliOptions struct {
		BPFProgPath              string
		AgentConfigPath          string
		CliFlag                  bool
		Debug                    bool
		Sdr                      bool
		K8sControllerWebhookPort int
		ContainerRuntime         bool
		DisableThreadEventStream bool
		// support for the eBPF ndoe agent running over host net_device dynamically reconfigure netpools for k8s CNI stop exfiltration from pod in user space or kernel sock layer, before it even reaches kernel host net_device traffic control
		Cni bool
		// used for sigkill with threshold limit for maslicious exfil detection
		SigKillBenignPortThreshold int
		SigKillTunnelPortThreshold int

		// enables the agent in data plane to enforce zero trust enforcement via a layered CA cert verification chain integrate LSM, keyring with global CA and PKI
		ControllerEnabledZtEnfoce bool
		ControllerRPCPort         int

		Profile bool
	}

	// apply addon and extend to support cusomt config as required by the agent in userspace
	AgentConfig interface {
		GetAgentAggressiveDpiMode() bool
		GetAddonFeaturesConfig() *EnhancedFeatures
		GetAgentConfig() *NodeAgentConfig
		ReadNodeAgentConfig(customConfigPath string) error
		GetL3FiltersConfig() *L3EnhancedFeatures
		GetRLimitConfig() *RlimitConfig
	}

	Config struct {
		AgentBootConfig *NodeAgentConfig
	}

	// config for high enhanced security for l3, l44, l7 filters and other orchestrated environments config to stop data breaches
	//  config usd to boot the DNS node agent in user space and inject kernel eBPF programs

	NodeAgentConfig struct {
		AgentModeAggressive bool `yaml:"agentModeAggressive" reflect:"agentModeAggressive"`
		AgentModeIsolated   bool `yaml:"agentModeIsolated" reflect:"agentModeIsolated"`
		StreamServers       struct {
			Host string `yaml:"host" reflect:"host"`
			Ip   string `yaml:"ip" reflect:"ip"`
			Port string `yaml:"port" reflect:"port"`
		} `yaml:"streamServers" reflect:"streamServers"`

		DNSServer struct {
			Host string `yaml:"host" reflect:"host"`
			Ip   string `yaml:"ip" reflect:"ip"`
			Port string `yaml:"port" reflect:"port"`
		} `yaml:"dnsServer" reflect:"dnsServer"`

		MetricServer struct {
			Host string `yaml:"host" reflect:"host"`
			Ip   string `yaml:"ip" reflect:"ip"`
			Port string `yaml:"port" reflect:"port"`
		} `yaml:"metricServer" reflect:"metricServer"`

		GrafanaServer struct {
			Host string `yaml:"host" reflect:"host"`
			Ip   string `yaml:"ip" reflect:"ip"`
			Port string `yaml:"port" reflect:"port"`
		} `yaml:"grafanaServer" reflect:"grafanaServer"`

		MetricsExporter struct {
			Port string `yaml:"port" reflect:"port"`
			Ip   string `yaml:"ip" reflect:"ip"`
		} `yaml:"metricsExporter" reflect:"metricsExporter"`

		DisableExporters struct {
			Streaming bool `yaml:"streaming" reflect:"streaming"`
			Metrics   bool `yaml:"metrics" reflect:"metrics"`
		} `yaml:"disableExporters" reflect:"disableExporters"`

		EnhancedFeatures EnhancedFeatures `yaml:"enhancedFeatures" reflect:"enhancedFeatures"`
		RlimitConfig     RlimitConfig     `yaml:"rlimitConfig" reflect:"rlimitConfig"`
	}

	DnsEnhancedFeatures struct {
		EnableNxFloodPrevention            bool `yaml:"enableNxFloodPrevention" reflect:"enableNxFloodPrevention"`
		EnableIngressSniff                 bool `yaml:"enableIngressSniff" reflect:"enableIngressSniff"`
		EnabledTbRlimit                    bool `yaml:"enabledTbRlimit" reflect:"enabledTbRlimit"`
		EnabbledVolumeRlimit               bool `yaml:"enabbledVolumeRlimit" reflect:"enabbledVolumeRlimit"`
		EnabledPassiveEgressEnhancedTCPDPI bool `yaml:"enabledPassiveEgressEnhancedTCPDPI"`
	}

	L3EnhancedFeatures struct {
		EnabledL3v4Filtering bool `yaml:"enabledL3v4Filtering" reflect:"enabledL3v4Filtering"`
		EnabledL3v6Filtering bool `yaml:"enabledL3v6Filtering" reflect:"enabledL3v6Filtering"`
	}

	EnhancedFeatures struct {
		Dns       DnsEnhancedFeatures `yaml:"dns" reflect:"dns"`
		L3Filters L3EnhancedFeatures  `yaml:"l3" reflect:"l3"`
	}

	RlimitConfig struct {
		Tb struct {
			MaxTokens int `yaml:"maxTokens" reflect:"maxTokens"`
		} `yaml:"tb" reflect:"tb"`
	}
)

// for global to be used by all endpoint security agent for live security enforcement
func ConfigureGlobalAgentCLiConfig(config *NodeAgentCliOptions) {
	GlobalAgentCliConfig = config
}

func NewNodeAgentConfig() *NodeAgentConfig {
	return &NodeAgentConfig{}
}

func (nn *Config) ReadNodeAgentConfig(customConfigPath string) error {
	var path string
	if customConfigPath != "" {
		path = customConfigPath
	} else {
		path = utils.NODE_CONFIG_FILE
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			utils.Log("Error cannot boot node daemon of ebpf with the base config file required {metrics, streamserver, dnsserver}")
			return err
		}
		utils.Logger.Printf("Erorr the config file exists but cannot be read %+v", err)
		return err
	}

	var config *NodeAgentConfig = NewNodeAgentConfig()

	ff, _ := os.ReadFile(path)

	if err := yaml.Unmarshal(ff, &config); err != nil {
		return err
	}

	nn.AgentBootConfig = config
	return nil
}

func (nn *Config) GetAgentAggressiveDpiMode() bool {
	return nn.AgentBootConfig.AgentModeAggressive
}

func (nn *Config) GetAgentConfig() *NodeAgentConfig {
	return nn.AgentBootConfig
}

func (nn *Config) GetAddonFeaturesConfig() *EnhancedFeatures {
	return &nn.AgentBootConfig.EnhancedFeatures
}

func (nn *Config) GetRLimitConfig() *RlimitConfig {
	return &nn.AgentBootConfig.RlimitConfig
}

func (nn *Config) GetL3FiltersConfig() *L3EnhancedFeatures {
	return &nn.AgentBootConfig.EnhancedFeatures.L3Filters
}
