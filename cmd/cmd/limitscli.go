/*
Copyright © 2024 Syncarcs
*/
package cmd

import (
	"github.com/spf13/cobra"
)

// limitscliCmd represents the limitscli command
var limitscliCmd = &cobra.Command{
	Use:   "limitscli",
	Short: "Reutrn the current configured limits for the node agent over DNS protocol",
	Run: func(cmd *cobra.Command, args []string) {
		GetCurrentBootedNodeAgentConfigLimits()
	},
}

func init() {
	rootCmd.AddCommand(limitscliCmd)

}
