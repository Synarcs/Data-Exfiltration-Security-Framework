/*
Copyright © 2024 Syncarcs
*/
package cmd

import (
	"github.com/spf13/cobra"
)

// bkingCmd represents the bking command
var bkingCmd = &cobra.Command{
	Use:   "bkingress",
	Short: "Returns the current State of the eBPF Node Agent and all blacklisted domains from kernel and user space in eBPF node Agent LRU cache for Ingress traffic",
	Run: func(cmd *cobra.Command, args []string) {
		GetCurrentBootedNodeAgentBlacklistedIngressDomainsSLD()
	},
}

func init() {
	rootCmd.AddCommand(bkingCmd)

}
