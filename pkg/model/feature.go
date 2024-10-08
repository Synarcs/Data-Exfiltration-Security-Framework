package model

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/google/gopacket/layers"
)

type DNSFeatures struct {
	UCaseCount         int
	NumberCount        int
	Entropy            float64
	LongestLabelDomain int
	LabelCount         int
	LengthofSubdomains int
}

func Entropy(dns_label *string) float64 {
	return 0
}

func LabelCountExcludeRootDomain(dns_label *string) int {
	return len(strings.Split(*dns_label, "."))
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func LengthMaxandTotalSubdomains(dns_label []string) (int, int, int, int, int) {
	mxLen := 0
	totoalLen := 0
	numCount := 0

	lowerCharCount := 0
	upperCharCount := 0
	for _, label := range dns_label {
		totoalLen += len(label)
		mxLen = max(mxLen, len(label))

		for _, val := range label {
			lbl := rune(val)
			if unicode.IsNumber(lbl) {
				numCount++
			} else if unicode.IsLower(lbl) {
				lowerCharCount++
			} else if unicode.IsUpper(lbl) {
				upperCharCount++
			}
		}
	}

	return mxLen, totoalLen, numCount, lowerCharCount, upperCharCount
}

func ProcessFeatures(dns_packet *layers.DNS) error {
	var features []DNSFeatures = make([]DNSFeatures, dns_packet.QDCount)

	for _, _ = range dns_packet.Answers {
	}

	for i, payload := range dns_packet.Questions {

		exclude_tld := strings.Split(string(payload.Name), ".")
		features[i].LabelCount = len(exclude_tld) - 2 // the kernel wount allow tld to be redirected to user space
		mx_len, totalLen, numberCount, _, upperCount := LengthMaxandTotalSubdomains(exclude_tld[:len(exclude_tld)-2])
		features[i].LongestLabelDomain = mx_len
		features[i].LengthofSubdomains = totalLen
		features[i].UCaseCount = upperCount
		features[i].NumberCount = numberCount

		mrsh, _ := json.Marshal(features[i])
		fmt.Println(string(mrsh))
	}

	for _, _ = range dns_packet.Authorities {
	}
	return nil
}
