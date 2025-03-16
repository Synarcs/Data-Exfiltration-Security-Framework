package cni

type NetworkPolicies interface {
	CreateL3NetworkPolicy([]string) error // ipv4 for now
	CreateL7NetworkPolicy([]string) error // DNS for now with all the fqdns
	GetCniVersion() string
	GetCniName() string
}
