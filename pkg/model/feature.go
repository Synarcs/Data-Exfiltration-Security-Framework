package model

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"strings"
	"unicode"

	"github.com/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/google/gopacket/layers"
)

type DNSFeatures struct {
	Fqdn                  string
	Tld                   string
	TotalChars            int
	TotalCharsInSubdomain int
	NumberCount           int
	UCaseCount            int
	LCaseCount            int
	SpecialCount          int
	Entropy               float32
	PeriodsInSubDomain    int
	LongestLabelDomain    int
	LengthofSubdomains    int
	AveerageLabelLength   float32
	IsEgress              bool
}

func GenerateFloatVectors(features []DNSFeatures) [][]float32 {
	floatTensors := make([][]float32, 0)
	for i := 0; i < len(features); i++ {
		perLabelFeatures := make([]float32, 8)
		perLabelFeatures[0] = float32(features[i].TotalChars)
		perLabelFeatures[1] = float32(features[i].TotalCharsInSubdomain)
		perLabelFeatures[2] = float32(features[i].NumberCount)
		perLabelFeatures[3] = float32(features[i].UCaseCount)
		perLabelFeatures[4] = float32(features[i].Entropy)
		perLabelFeatures[5] = float32(features[i].PeriodsInSubDomain)
		perLabelFeatures[6] = float32(features[i].LongestLabelDomain)
		perLabelFeatures[7] = float32(features[i].AveerageLabelLength)
		floatTensors = append(floatTensors, perLabelFeatures)
	}

	return floatTensors
}

func GenerateDnsParserModelUtils(ifaceHandler *netinet.NetIface, onnxModel *OnnxModel) *DnsPacketGen {
	xdpSocketFd, err := ifaceHandler.GetRootNamespaceRawSocketFdXDP()

	if err == nil {
		log.Println("[x] Using the raw packet with AF_PACKET Fd")

		return &DnsPacketGen{
			IfaceHandler:        ifaceHandler,
			SockSendFdInterface: ifaceHandler.PhysicalLinks,
			XdpSocketSendFd:     xdpSocketFd,
			SocketSendFd:        nil,
			OnnxModel:           onnxModel,
		}
	} else {
		log.Println("Error Binding the XDP Socket Physical driver lacking support")
		fd, err := ifaceHandler.GetRootNamespaceRawSocketFd()

		if err != nil {
			log.Fatalln("Error fetching the raw socket fd for the socket")
			panic(err.Error())
		}

		return &DnsPacketGen{
			IfaceHandler:        ifaceHandler,
			SockSendFdInterface: ifaceHandler.PhysicalLinks,
			SocketSendFd:        fd,
			XdpSocketSendFd:     nil,
			OnnxModel:           onnxModel,
		}
	}
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

func Entropy(dns_label []string) float32 {
	return float32(EntropyLabel(strings.Join(dns_label, "")))
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

func ProcessDnsFeatures(dns_packet *layers.DNS, isEgress bool) ([]DNSFeatures, error) {
	var features []DNSFeatures = make([]DNSFeatures, dns_packet.QDCount+dns_packet.ANCount+dns_packet.ARCount)

	// do feature engineering over the entire dns payload section for enhancec lex analysis over each
	i := 0

	for _, payload := range dns_packet.Questions {
		exclude_tld := strings.Split(string(payload.Name), ".")
		features[i].PeriodsInSubDomain = len(exclude_tld) - 2 // the kernel wount allow only tld to be redirected to user space for enhanced lexical scanning
		mx_len, totalLen := LongestandTotoalLenSubdomains(exclude_tld[:len(exclude_tld)-2])
		features[i].LongestLabelDomain = mx_len
		features[i].LengthofSubdomains = totalLen

		ucount, lcount, ncount := DomainVarsCount(strings.Join(exclude_tld[:len(exclude_tld)-2], ""))

		features[i].UCaseCount = ucount
		features[i].NumberCount = ncount
		features[i].LCaseCount = lcount
		features[i].Tld = exclude_tld[len(exclude_tld)-2]
		features[i].Fqdn = string(payload.Name)
		features[i].Entropy = Entropy(exclude_tld[:len(exclude_tld)-2])
		features[i].IsEgress = isEgress
		mrsh, _ := json.Marshal(features[i])
		fmt.Println(string(mrsh))
		i += 1
	}

	if len(dns_packet.Answers) > 0 {
		for _, payload := range dns_packet.Answers {
			exclude_tld := strings.Split(string(payload.Name), ".")
			if len(exclude_tld) > 2 {
				features[i].PeriodsInSubDomain = len(exclude_tld) - 2 // the kernel wount allow tld to be redirected to user space
				mx_len, totalLen := LongestandTotoalLenSubdomains(exclude_tld[:len(exclude_tld)-2])
				features[i].LongestLabelDomain = mx_len
				features[i].LengthofSubdomains = totalLen

				ucount, lcount, ncount := DomainVarsCount(strings.Join(exclude_tld[:len(exclude_tld)-2], ""))

				features[i].UCaseCount = ucount
				features[i].NumberCount = ncount
				features[i].LCaseCount = lcount
				features[i].Tld = exclude_tld[len(exclude_tld)-2]

				features[i].IsEgress = isEgress

				features[i].Fqdn = string(payload.Name)

				features[i].Entropy = Entropy(exclude_tld[:len(exclude_tld)-2])
				mrsh, _ := json.Marshal(features[i])
				fmt.Println(string(mrsh))
			}
		}
	}

	if len(dns_packet.Additionals) > 0 {
		for _, payload := range dns_packet.Additionals {
			exclude_tld := strings.Split(string(payload.Name), ".")
			if len(exclude_tld) > 2 {
				features[i].PeriodsInSubDomain = len(exclude_tld) - 2 // the kernel wount allow tld to be redirected to user space
				mx_len, totalLen := LongestandTotoalLenSubdomains(exclude_tld[:len(exclude_tld)-2])
				features[i].LongestLabelDomain = mx_len
				features[i].LengthofSubdomains = totalLen

				ucount, lcount, ncount := DomainVarsCount(strings.Join(exclude_tld[:len(exclude_tld)-2], ""))

				features[i].UCaseCount = ucount
				features[i].NumberCount = ncount
				features[i].LCaseCount = lcount
				features[i].Tld = exclude_tld[len(exclude_tld)-2]

				features[i].IsEgress = isEgress

				features[i].Fqdn = string(payload.Name)

				features[i].Entropy = Entropy(exclude_tld[:len(exclude_tld)-2])
				mrsh, _ := json.Marshal(features[i])
				fmt.Println(string(mrsh))
			}
		}
	}

	return features, nil
}
