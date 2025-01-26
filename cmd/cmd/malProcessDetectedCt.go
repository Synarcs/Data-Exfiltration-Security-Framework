/*
Copyright © 2025 Synarcs
*/
package cmd

import (
	"github.com/spf13/cobra"
)

// malProcessDetectedCtCmd represents the malProcessDetectedCt command
var malProcessDetectedCtCmd = &cobra.Command{
	Use:   "malProcessDetectedCt",
	Short: "Returns all the malicious detected processOd on the node",
	Long: `All the malicious process Id detected by the eBPF node agent used to kill the this process by using kernel syscall layer for ensureing
				the same process does not continue to retry, as the eBPF node agent blocks all its exfiltration attempts, after certain threshold the process will be killed`,
	Run: func(cmd *cobra.Command, args []string) {
		GetMaliciousDetectedProcessCtOnNode()
	},
}

func init() {
	rootCmd.AddCommand(malProcessDetectedCtCmd)
}
