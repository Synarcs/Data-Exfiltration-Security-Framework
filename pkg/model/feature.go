package model

import (
	"fmt"

	"github.com/google/gopacket/layers"
)

func Entropy(dns_label *string) float64 {
	return 0
}

func LabelCount(dns_label *string) int32 {
	return -1
}

func ProcessFeatures(dns_packet *layers.DNS) error {
	if dns_packet.ANCount > 0 {
		for _, payload := range dns_packet.Answers {
			fmt.Println(payload)
		}
	}

	if dns_packet.QDCount > 0 {
		for _, payload := range dns_packet.Questions {
			fmt.Println(payload)

		}
	}

	if dns_packet.ARCount > 0 {
		for _, payload := range dns_packet.Authorities {
			fmt.Println(payload)
		}
	}
	return nil
}
