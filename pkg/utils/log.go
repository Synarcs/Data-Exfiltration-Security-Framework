/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
*/

package utils

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
)

var (
	once   sync.Once
	Logger *log.Logger = nil
)

func Log(args ...any) {
	Logger.Info(strings.TrimSuffix(fmt.Sprintln(args...), "\n"))
}

func InitLogger() {
	Logger = log.NewWithOptions(os.Stderr, log.Options{
		ReportTimestamp: true,
		TimeFormat:      time.RFC822,
	})
	Logger.SetFormatter(log.TextFormatter)
}

// add functional optional pattern if more customized logger is required
func NewLogger(ctx context.Context) {
	once.Do(InitLogger)
}
