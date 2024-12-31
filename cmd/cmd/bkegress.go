/*
Copyright © 2024 Syncarcs
*/
package cmd

import (
	"github.com/spf13/cobra"
)

// bkegressCmd represents the bkegress command
var bkegressCmd = &cobra.Command{
	Use:   "bkegress",
	Short: "Returns the current State of the eBPF Node Agent and all blacklisted domains from kernel and user space in eBPF node Agent LRU cache for egress traffic",
	Run: func(cmd *cobra.Command, args []string) {
		GetCurrentBootedNodeAgentBlacklistedEgressDomainsSLD()
	},
}

func init() {
	rootCmd.AddCommand(bkegressCmd)
}
