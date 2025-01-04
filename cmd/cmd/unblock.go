/*
Copyright © 2025 Syncarcs
*/
package cmd

import (
	"log"
	"strings"

	"github.com/spf13/cobra"
)

// unblockCmd represents the unblock command
var unblockCmd = &cobra.Command{
	Use:   "unblock",
	Short: "Unblock a domain over for local node-agent cache running the eBPF Agent communicated with eBPF programs in kernel",
	Long:  "Used to unblock a currently blaclisted SLD in local eBPF node-agent LRU cache..",
	Run: func(cmd *cobra.Command, args []string) {
		for _, domain := range args {
			log.Printf("Triggered and unblocking the domain %+v", domain)
			UnblockDomain(strings.TrimSpace(domain))
		}
	},
}

func init() {
	rootCmd.AddCommand(unblockCmd)
}
