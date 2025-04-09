package conf

import (
	"errors"
	"log"
	"os"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"gopkg.in/yaml.v2"
)

// cli agent config for booting the node agent at the endpoitn

type NodeAgentCliOptions struct {
	CliFlag                  bool
	Debug                    bool
	StreamClient             bool
	Sdr                      bool
	K8sControllerWebhookPort int
	ContainerRuntime         bool
	// support for the eBPF ndoe agent running over host net_device dynamically reconfigure netpools for k8s CNI stop exfiltration from pod in user space or kernel sock layer, before it even reaches kernel host net_device traffic control
	Cni bool
	// used for sigkill with threshold limit for maslicious exfil detection
	SigKill int

	Profile bool
}

// apply addon and extend to support cusomt config as required by the agent in userspace
type AgentConfig interface {
	GetAddonFeaturesConfig() *EnhancedFeatures
	GetAgentConfig() *NodeAgentConfig
	ReadNodeAgentConfig() error
	GetL3FiltersConfig() *L3EnhancedFeatures
	GetRLimitConfig() *RlimitConfig
}

type Config struct {
	AgentBootConfig *NodeAgentConfig
}

func (nn *Config) ReadNodeAgentConfig() error {

	if _, err := os.Stat(utils.NODE_CONFIG_FILE); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Println("Error cannot boot node daemon of ebpf with the base config file required {metrics, streamserver, dnsserver}")
			return err
		}
		log.Printf("Erorr the config file exists but cannot be read %+v", err)
		return err
	}

	var config *NodeAgentConfig = &NodeAgentConfig{}

	ff, _ := os.ReadFile(utils.NODE_CONFIG_FILE)

	if err := yaml.Unmarshal(ff, &config); err != nil {
		return err
	}

	nn.AgentBootConfig = config
	return nil
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

// config for high enhanced security for l3, l44, l7 filters and other orchestrated environments config to stop data breaches
//  config usd to boot the DNS node agent in user space and inject kernel eBPF programs

type NodeAgentConfig struct {
	StreamServers struct {
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

type DnsEnhancedFeatures struct {
	EnableNxFloodPrevention      bool `yaml:"enableNxFloodPrevention" reflect:"enableNxFloodPrevention"`
	EnableIngressSniff           bool `yaml:"enableIngressSniff" reflect:"enableIngressSniff"`
	EnabledTbRlimit              bool `yaml:"enabledTbRlimit" reflect:"enabledTbRlimit"`
	EnabbledVolumeRlimit         bool `yaml:"enabbledVolumeRlimit" reflect:"enabbledVolumeRlimit"`
	EnabledPassiveEnhancedTCPDPI bool `yaml:"enabledPassiveEnhancedTCPDPI"`
}

type L3EnhancedFeatures struct {
	EnabledL3v4Filtering bool `yaml:"enabledL3v4Filtering" reflect:"enabledL3v4Filtering"`
	EnabledL3v6Filtering bool `yaml:"enabledL3v6Filtering" reflect:"enabledL3v6Filtering"`
}

type EnhancedFeatures struct {
	Dns       DnsEnhancedFeatures `yaml:"dns" reflect:"dns"`
	L3Filters L3EnhancedFeatures  `yaml:"l3" reflect:"l3"`
}

type RlimitConfig struct {
	Tb struct {
		MaxTokens int `yaml:"maxTokens" reflect:"maxTokens"`
	} `yaml:"tb" reflect:"tb"`
}
