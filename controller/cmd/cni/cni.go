package cni

import (
	"context"

	"github.com/Synarcs/DNSObelisk/controller/conf"
)

type NetworkPolicies interface {
	CreateL3NetworkPolicy(context.Context, []string) error // ipv4 for now
	CreateL7NetworkPolicy(context.Context, []string) error // DNS for now with all the fqdns
	GetK8sClusterHost(*conf.GlobalControllerConfig) string
	GetCniName(*conf.GlobalControllerConfig) string
}
