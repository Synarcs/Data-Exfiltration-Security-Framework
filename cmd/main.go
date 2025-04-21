/*
Copyright © 2024 Syncarcs
*/
package main

import (
	"context"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/cmd/cmd"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
)

func main() {
	ctx := context.Background()

	utils.NewLogger(ctx)
	cmd.Execute()
}
