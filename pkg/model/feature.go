package model

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"unicode"

	"github.com/google/gopacket/layers"
)

type DNSFeatures struct {
	UCaseCount         int
	LCaseCount         int
	NumberCount        int
	SpecialCount       int
	Entropy            float64
	LongestLabelDomain int
	LabelCount         int
	LengthofSubdomains int
}

type DnsFeaturesEngine struct {
	onnxModel *OnnxModel
}

func EntropyLabel(dns_label string) float64 {
	var freq map[rune]int = make(map[rune]int)
	for _, val := range dns_label {
		_, ok := freq[val]
		if !ok {
			freq[val] = 1
		} else {
			freq[val]++
		}
	}

	entropy := 0.0
	length := float64(len(dns_label))

	for _, ct := range freq {
		p := float64(ct) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func Entropy(dns_label []string) float64 {
	return EntropyLabel(strings.Join(dns_label, ""))
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

func LongestandTotoalLenSubdomains(dns_label []string) (int, int) {
	mxLen := 0
	totalLen := 0

	for _, label := range dns_label {
		totalLen += len(label)
		mxLen = max(mxLen, len(label))
	}

	fmt.Println("the upper count and lowe count are ")
	return mxLen, totalLen
}

func DomainVarsCount(dns_label string) (int, int, int) {
	ucount, lcount, ncount := 0, 0, 0

	for _, val := range dns_label {
		if unicode.IsNumber(val) {
			ncount++
		}
		if unicode.IsLower(val) {
			lcount++
		}
		if unicode.IsUpper(val) {
			ucount++
		}
	}
	return ucount, lcount, ncount
}

func (f *DnsFeaturesEngine) ProcessFeatures(dns_packet *layers.DNS) error {
	var features []DNSFeatures = make([]DNSFeatures, dns_packet.QDCount)

	for _, _ = range dns_packet.Answers {
	}

	for i, payload := range dns_packet.Questions {

		exclude_tld := strings.Split(string(payload.Name), ".")
		features[i].LabelCount = len(exclude_tld) - 2 // the kernel wount allow tld to be redirected to user space
		mx_len, totalLen := LongestandTotoalLenSubdomains(exclude_tld[:len(exclude_tld)-2])
		features[i].LongestLabelDomain = mx_len
		features[i].LengthofSubdomains = totalLen

		ucount, lcount, ncount := DomainVarsCount(strings.Join(exclude_tld[:len(exclude_tld)-2], ""))

		features[i].UCaseCount = ucount
		features[i].NumberCount = ncount
		features[i].LCaseCount = lcount

		features[i].Entropy = Entropy(exclude_tld[:len(exclude_tld)-2])
		mrsh, _ := json.Marshal(features[i])
		fmt.Println(string(mrsh))
	}

	for _, _ = range dns_packet.Authorities {
	}

	return nil
}
