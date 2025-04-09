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

// add functional optional pattern if more customized logger is required
func NewLogger(ctx context.Context) {
	once.Do(func() {
		Logger = log.NewWithOptions(os.Stderr, log.Options{
			ReportTimestamp: true,
			TimeFormat:      time.RFC822,
		})
		Logger.SetFormatter(log.LogfmtFormatter)
		Logger.SetPrefix("msg")
	})
}
