package cni

import "github.com/Synarcs/DNSObelisk/controller/conf"

type NetworkPolicies interface {
	CreateL3NetworkPolicy([]string) error // ipv4 for now
	CreateL7NetworkPolicy([]string) error // DNS for now with all the fqdns
	GetK8sClusterHost(*conf.GlobalControllerConfig) string
	GetCniName(*conf.GlobalControllerConfig) string
}
