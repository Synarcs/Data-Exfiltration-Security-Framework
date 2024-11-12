package model

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"strings"
	"unicode"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/google/gopacket/layers"
)

type DNSFeatures struct {
	Fqdn                  string
	Tld                   string
	Subdomain             string
	TotalChars            int
	TotalCharsInSubdomain int // holds the chars which are unicode encodable and can be stored
	NumberCount           int
	UCaseCount            int
	LCaseCount            int
	Entropy               float32
	Periods               int
	PeriodsInSubDomain    int
	LongestLabelDomain    int
	AveerageLabelLength   float32
	IsEgress              bool
	AuthZoneSoaservers    map[string]string // zone master --> mx record type
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

func ParseDnsQuestions(dns_packet *layers.DNS, features []DNSFeatures, isEgress bool, i int) ([]DNSFeatures, error) {
	parseEachQuerySection := func(exclude_tld []string, payload layers.DNSQuestion) {
		features[i].Periods = strings.Count(string(payload.Name), ".")
		features[i].PeriodsInSubDomain = features[i].Periods - 2 // the kernel wount allow non tld to be redirected to user space
		features[i].TotalChars = len(payload.Name) - features[i].Periods

		features[i].Subdomain = strings.Join(exclude_tld[:len(exclude_tld)-2], ".")
		features[i].PeriodsInSubDomain = len(exclude_tld) - 2 // kernel wount allow only tld to be redirected to user space for enhanced lexical scanning
		mx_len, totalLen := LongestandTotoalLenSubdomains(exclude_tld[:len(exclude_tld)-2])
		features[i].LongestLabelDomain = mx_len
		features[i].TotalCharsInSubdomain = totalLen

		ucount, lcount, ncount := DomainVarsCount(strings.Join(exclude_tld[:len(exclude_tld)-2], ""))

		features[i].UCaseCount = ucount
		features[i].NumberCount = ncount
		features[i].LCaseCount = lcount
		features[i].Tld = strings.Join(exclude_tld[len(exclude_tld)-2:], ".")
		features[i].Fqdn = string(payload.Name)
		features[i].Entropy = Entropy(exclude_tld[:len(exclude_tld)-2])
		features[i].IsEgress = isEgress
	}

	singleQuery := len(dns_packet.Questions) == 1
	for _, payload := range dns_packet.Questions {

		exclude_tld := strings.Split(string(payload.Name), ".")
		if singleQuery {
			parseEachQuerySection(exclude_tld, payload)
		} else {
			if len(exclude_tld) > 2 {
				parseEachQuerySection(exclude_tld, payload)
			}
		}

		i += 1
	}
	return features, nil
}

// for now verify and drop if its mail or null records
func CheckMxTxtNullRecordInQuestions(dns_packet *layers.DNS, features []DNSFeatures) bool {
	for _, payload := range dns_packet.Questions {
		if payload.Type == layers.DNSTypeMX || payload.Type == layers.DNSTypeTXT || payload.Type == layers.DNSTypeNULL {
			return true
		}
	}
	return false
}

func ParseDnsAnswers(dns_packet *layers.DNS, features []DNSFeatures, isEgress bool, i int) ([]DNSFeatures, error) {
	for _, payload := range dns_packet.Answers {
		exclude_tld := strings.Split(string(payload.Name), ".")
		if len(exclude_tld) > 2 {
			features[i].PeriodsInSubDomain = len(exclude_tld) - 2 // the kernel wount allow tld to be redirected to user space
			mx_len, totalLen := LongestandTotoalLenSubdomains(exclude_tld[:len(exclude_tld)-2])
			features[i].LongestLabelDomain = mx_len
			features[i].TotalCharsInSubdomain = totalLen

			ucount, lcount, ncount := DomainVarsCount(strings.Join(exclude_tld[:len(exclude_tld)-2], ""))

			features[i].UCaseCount = ucount
			features[i].NumberCount = ncount
			features[i].LCaseCount = lcount
			features[i].Tld = strings.Join(exclude_tld[len(exclude_tld)-2:], ".")

			features[i].IsEgress = isEgress

			features[i].Fqdn = string(payload.Name)

			features[i].Entropy = Entropy(exclude_tld[:len(exclude_tld)-2])
			mrsh, _ := json.Marshal(features[i])
			fmt.Println(string(mrsh))
		}
	}
	return features, nil
}

func ParseDnsAuth(dns_packet *layers.DNS, features []DNSFeatures, isEgress bool, i int) ([]DNSFeatures, error) {
	for _, payload := range dns_packet.Authorities {
		if payload.Type == layers.DNSTypeSOA || payload.Type == layers.DNSTypeOPT {
			continue
		}
		var feature DNSFeatures
		exclude_tld := strings.Split(string(payload.Name), ".")
		if len(exclude_tld) > 2 {
			features[i].PeriodsInSubDomain = len(exclude_tld) - 2 // the kernel wount allow tld to be redirected to user space
			mx_len, totalLen := LongestandTotoalLenSubdomains(exclude_tld[:len(exclude_tld)-2])
			feature.LongestLabelDomain = mx_len

			feature.TotalCharsInSubdomain = totalLen

			ucount, lcount, ncount := DomainVarsCount(strings.Join(exclude_tld[:len(exclude_tld)-2], ""))

			feature.UCaseCount = ucount
			feature.NumberCount = ncount
			feature.LCaseCount = lcount
			feature.Tld = strings.Join(exclude_tld[len(exclude_tld)-2:], ".")

			feature.IsEgress = isEgress

			feature.Fqdn = string(payload.Name)

			feature.Entropy = Entropy(exclude_tld[:len(exclude_tld)-2])
			features = append(features, feature)
			mrsh, _ := json.Marshal(features[i])
			fmt.Println(string(mrsh))
		}
	}
	return features, nil
}

func ParseDnsAdditional(dns_packet *layers.DNS, features []DNSFeatures, isEgress bool, i int) ([]DNSFeatures, error) {
	for _, payload := range dns_packet.Additionals {
		// TODOD: An additional record with non standard OPT type or EDNS
		var feature DNSFeatures
		if payload.Type == layers.DNSTypeOPT || payload.Type == layers.DNSTypeSOA {
			continue
		}
		exclude_tld := strings.Split(string(payload.Name), ".")
		if len(exclude_tld) > 2 {
			feature.PeriodsInSubDomain = len(exclude_tld) - 2 // the kernel wount allow tld to be redirected to user space
			mx_len, totalLen := LongestandTotoalLenSubdomains(exclude_tld[:len(exclude_tld)-2])
			feature.LongestLabelDomain = mx_len
			feature.TotalCharsInSubdomain = totalLen

			ucount, lcount, ncount := DomainVarsCount(strings.Join(exclude_tld[:len(exclude_tld)-2], ""))

			feature.UCaseCount = ucount
			feature.NumberCount = ncount
			feature.LCaseCount = lcount
			feature.Tld = strings.Join(exclude_tld[len(exclude_tld)-2:], ".")

			feature.IsEgress = isEgress

			feature.Fqdn = string(payload.Name)

			feature.Entropy = Entropy(exclude_tld[:len(exclude_tld)-2])
			features = append(features, feature)
			mrsh, _ := json.Marshal(features[i])
			fmt.Println(string(mrsh))
		}
	}
	return features, nil
}

func ProcessDnsFeatures(dns_packet *layers.DNS, isEgress bool) ([]DNSFeatures, error) {
	var features []DNSFeatures

	/*
		A DNS data breach often involve dns queries to the remote c2c
			1. DNS tunnelling: alwauys have questions, additional stuffed with dns payload
			2. DNS c2c, always questions over the questions, additional, auth (non soa) section stuff with dns payload
	*/

	i := 0
	isIngress := !isEgress

	if isEgress {
		features = make([]DNSFeatures, dns_packet.QDCount)
	} else {
		features = make([]DNSFeatures, dns_packet.ANCount)
	}

	if len(dns_packet.Questions) > 0 && isEgress {
		features, _ = ParseDnsQuestions(dns_packet, features, isEgress, i)
		i += len(features)
	}

	if len(dns_packet.Answers) > 0 && isIngress {
		features, _ = ParseDnsAnswers(dns_packet, features, isEgress, i)
		i += len(features)
	}

	// used for mdns and edns based parsing when addon dns querstios are passed
	//  the malware can send more malicious information in the addon section to bypass detection
	if len(dns_packet.Additionals) > 0 && (isIngress || isEgress) {
		features, _ = ParseDnsAdditional(dns_packet, features, isEgress, i)
		i += len(features)
	}

	if len(dns_packet.Authorities) > 0 && isEgress {
		features, _ = ParseDnsAuth(dns_packet, features, isEgress, i)
		i += len(features)
	}

	if !utils.DEBUG {
		log.Println("[x] Total Raw Process Features extracetd for the DNS Packet is ", len(features))
		for _, feature := range features {
			mrsh, _ := json.Marshal(feature)
			fmt.Println(string(mrsh))
		}
	}

	return features, nil
}
