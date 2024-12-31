/*
Copyright © 2024 Syncarcs
*/
package cmd

import (
	"log"
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:           "Data Exfiltration Security Framework eBPF Node Agent cli",
	Short:         "CLI to interact eBPF Node Agent local unix socket",
	Long:          "An Enhanced Enterprise Ready Data Exfiltration Security Framework buildi for distributed enviornments usine eBPF (linux kernel tc, xdp, kprobes,  kfuncs), Deep Learning and Threat Data Streaming",
	Version:       "0.0.1",
	SilenceErrors: false,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if definedCobraDigitalOcean here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cmd.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
