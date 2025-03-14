package conf

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
}

type DnsEnhancedFeatures struct {
	EnableNxFloodPrevention bool `yaml:"enableNxFloodPrevention" reflect:"enableNxFloodPrevention"`
	EnableIngressSniff      bool `yaml:"enableIngressSniff" reflect:"enableIngressSniff"`
}

type L3EnhancedFeatures struct {
	EnabledL3Filtering bool `yaml:"enabledL3Filtering" reflect:"enabledL3Filtering"`
}

type EnhancedFeatures struct {
	Dns       DnsEnhancedFeatures `yaml:"dns" reflect:"dns"`
	L3Filters L3EnhancedFeatures  `yaml:"l3" reflect:"l3"`
}
