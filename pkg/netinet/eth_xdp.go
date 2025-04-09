package netinet

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
)

func GetCurrentTXQueues(interfaceName string) (int, error) {
	cmd := exec.Command("ethtool", "-l", interfaceName)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return 0, err
	}

	// Adjusted regular expression to work across multiple lines
	rx := regexp.MustCompile(`(?s)Current hardware settings:.*?TX:\s+(\d+)`)
	matches := rx.FindStringSubmatch(out.String())
	if len(matches) < 2 {
		// If the TX queues are not found, try to find the combined queues
		// tradionally a vm on any cpu arch combines tx and rx queues for optimized packet transfer via veth
		rx = regexp.MustCompile(`(?s)Current hardware settings:.*?Combined:\s+(\d+)`)
		matches = rx.FindStringSubmatch(out.String())
		if len(matches) < 2 {
			utils.Log("could not find TX queues in output")
			return 0, fmt.Errorf("could not find TX queues in output")
		}
	}
	var txQueues int
	fmt.Sscanf(matches[1], "%d", &txQueues)

	return txQueues, nil
}

func GetCurrentRXQuees(interfaceName string) (int, error) {
	cmd := exec.Command("ethtool", "-l", interfaceName)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return 0, err
	}

	// Adjusted regular expression to work across multiple lines
	rx := regexp.MustCompile(`(?s)Current hardware settings:.*?RX:\s+(\d+)`)
	matches := rx.FindStringSubmatch(out.String())
	if len(matches) < 2 {
		// If the TX queues are not found, try to find the combined queues
		// tradionally a vm on any cpu arch combines tx and rx queues for optimized packet transfer via veth
		rx = regexp.MustCompile(`(?s)Current hardware settings:.*?Combined:\s+(\d+)`)
		matches = rx.FindStringSubmatch(out.String())
		if len(matches) < 2 {
			utils.Log("could not find RX queues in output")
			return 0, fmt.Errorf("could not find RX queues in output")
		}
	}
	var txQueues int
	fmt.Sscanf(matches[1], "%d", &txQueues)

	return txQueues, nil
}
