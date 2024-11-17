package model

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"regexp"
	"strings"
	"unicode"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
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
	Entropy               float32
	Periods               int
	PeriodsInSubDomain    int
	LongestLabelDomain    int
	AverageLabelLength    float32
	IsEgress              bool
	RecordType            string
	AuthZoneSoaservers    map[string]string // zone master --> mx record type
}

func GenerateDnsParserModelUtils(ifaceHandler *netinet.NetIface,
	onnxModel *OnnxModel, streamClient *events.StreamProducer) *DnsPacketGen {
	xdpSocketFd, err := ifaceHandler.GetRootNamespaceRawSocketFdXDP()

	if err == nil {
		log.Println("[x] Using the raw packet with AF_PACKET Fd")

		return &DnsPacketGen{
			IfaceHandler:        ifaceHandler,
			SockSendFdInterface: ifaceHandler.PhysicalLinks,
			XdpSocketSendFd:     xdpSocketFd,
			SocketSendFd:        nil,
			OnnxModel:           onnxModel,
			StreamClient:        streamClient,
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
			StreamClient:        streamClient,
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

func LongestandTotoalLenSubdomains(dns_label []string) (int, int, float32) {
	mxLen := 0
	totalLen := 0
	var avglen float32

	for _, label := range dns_label {
		totalLen += len(label)
		mxLen = max(mxLen, len(label))
	}

	avglen = float32(totalLen / len(dns_label))
	return mxLen, totalLen, avglen
}

func DomainVarsCount(dns_label string) (int, int, int) {
	ucount, lcount, ncount := 0, 0, 0

	special := regexp.MustCompile("[!@#$%^&*]")
	if len(special.Find([]byte(dns_label))) > 0 {

	}

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
	parseEachQuerySection := func(dns_query_labels []string, payload layers.DNSQuestion) {
		features[i].Periods = len(dns_query_labels) - 1                                      // total dots
		features[i].PeriodsInSubDomain = len(dns_query_labels[:len(dns_query_labels)-2]) - 1 // the kernel wount allow non tld to be redirected to user space
		features[i].TotalChars = len(payload.Name) - features[i].Periods
		features[i].TotalCharsInSubdomain = len(strings.Join(dns_query_labels[:len(dns_query_labels)-2], ""))

		ucount, _, ncount := DomainVarsCount(strings.Join(dns_query_labels[:len(dns_query_labels)-2], ""))

		features[i].NumberCount = ncount
		features[i].UCaseCount = ucount
		features[i].Entropy = Entropy(dns_query_labels)

		features[i].Subdomain = strings.Join(dns_query_labels[:len(dns_query_labels)-2], ".")
		features[i].PeriodsInSubDomain = len(dns_query_labels) - 2 // kernel wount allow only tld to be redirected to user space for enhanced lexical scanning
		mx_len, _, avgLen := LongestandTotoalLenSubdomains(dns_query_labels)
		features[i].LongestLabelDomain = mx_len
		features[i].AverageLabelLength = avgLen

		features[i].Tld = strings.Join(dns_query_labels[len(dns_query_labels)-2:], ".")
		features[i].Fqdn = string(payload.Name)
		features[i].IsEgress = isEgress
		features[i].RecordType = payload.Type.String()
	}

	singleQuery := len(dns_packet.Questions) == 1
	var recordTypes map[string]int = make(map[string]int)
	payload := dns_packet.Questions[0]
	dns_query_labels := strings.Split(string(payload.Name), ".")
	if singleQuery {
		_, ok := recordTypes[payload.Type.String()]
		if !ok {
			recordTypes[payload.Type.String()] = 1
		} else {
			recordTypes[payload.Type.String()] += 1
		}
		parseEachQuerySection(dns_query_labels, payload)
	} else {
		for _, payload := range dns_packet.Questions {
			_, ok := recordTypes[payload.Type.String()]
			if !ok {
				recordTypes[payload.Type.String()] = 1
			} else {
				recordTypes[payload.Type.String()] += 1
			}
			parseEachQuerySection(dns_query_labels, payload)
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

func ParseDnsAnswers(dns_packet *layers.DNS, features []DNSFeatures, isEgress bool) ([]DNSFeatures, error) {
	for _, payload := range dns_packet.Answers {
		dns_query_labels := strings.Split(string(payload.Name), ".")
		feature := DNSFeatures{}
		if len(dns_query_labels) > 2 {
			feature.Periods = len(dns_query_labels) - 1                                      // total dots
			feature.PeriodsInSubDomain = len(dns_query_labels[:len(dns_query_labels)-2]) - 1 // the kernel wount allow non tld to be redirected to user space
			feature.TotalChars = len(payload.Name) - feature.Periods
			feature.TotalCharsInSubdomain = len(strings.Join(dns_query_labels[:len(dns_query_labels)-2], ""))

			ucount, _, ncount := DomainVarsCount(strings.Join(dns_query_labels[:len(dns_query_labels)-2], ""))
			feature.NumberCount = ncount
			feature.UCaseCount = ucount
			feature.Entropy = Entropy(dns_query_labels[:len(dns_query_labels)-2])

			feature.Subdomain = strings.Join(dns_query_labels[:len(dns_query_labels)-2], ".")
			feature.PeriodsInSubDomain = len(dns_query_labels) - 2 // kernel wount allow only tld to be redirected to user space for enhanced lexical scanning
			mx_len, _, avgLen := LongestandTotoalLenSubdomains(dns_query_labels)
			feature.LongestLabelDomain = mx_len
			feature.AverageLabelLength = avgLen
			feature.IsEgress = false

			feature.Fqdn = string(payload.Name)
			feature.Tld = strings.Join(dns_query_labels[len(dns_query_labels)-2:], ".")
			feature.RecordType = payload.Type.String()
			features = append(features, feature)
			mrsh, _ := json.Marshal(features)

			if utils.DEBUG {
				log.Println(mrsh)
			}
		}
	}
	return features, nil
}

func ParseDnsAuth(dns_packet *layers.DNS, features []DNSFeatures, isEgress bool) ([]DNSFeatures, error) {
	for _, payload := range dns_packet.Authorities {
		if payload.Type == layers.DNSTypeSOA || payload.Type == layers.DNSTypeOPT {
			continue
		}
		var feature DNSFeatures
		dns_query_labels := strings.Split(string(payload.Name), ".")
		if len(dns_query_labels) > 2 {
			feature.Periods = len(dns_query_labels) - 1                                      // total dots
			feature.PeriodsInSubDomain = len(dns_query_labels[:len(dns_query_labels)-2]) - 1 // the kernel wount allow non tld to be redirected to user space
			feature.TotalChars = len(payload.Name) - feature.Periods
			feature.TotalCharsInSubdomain = len(strings.Join(dns_query_labels[:len(dns_query_labels)-2], ""))

			ucount, _, ncount := DomainVarsCount(strings.Join(dns_query_labels[:len(dns_query_labels)-2], ""))

			feature.NumberCount = ncount
			feature.UCaseCount = ucount
			feature.Entropy = Entropy(dns_query_labels[:len(dns_query_labels)-2])

			feature.Subdomain = strings.Join(dns_query_labels[:len(dns_query_labels)-2], ".")
			feature.PeriodsInSubDomain = len(dns_query_labels) - 2 // kernel wount allow only tld to be redirected to user space for enhanced lexical scanning
			mx_len, _, avgLen := LongestandTotoalLenSubdomains(dns_query_labels)
			feature.LongestLabelDomain = mx_len
			feature.AverageLabelLength = avgLen

			feature.Tld = strings.Join(dns_query_labels[len(dns_query_labels)-2:], ".")
			feature.Fqdn = string(payload.Name)
			feature.IsEgress = isEgress
			feature.RecordType = payload.Type.String()

			features = append(features, feature)
			mrsh, _ := json.Marshal(feature)
			if utils.DEBUG {
				fmt.Println(string(mrsh))
			}
		}
	}
	return features, nil
}

func ParseDnsAdditional(dns_packet *layers.DNS, features []DNSFeatures, isEgress bool) ([]DNSFeatures, error) {
	for _, payload := range dns_packet.Additionals {
		// TODOD: An additional record with non standard OPT type or EDNS
		var feature DNSFeatures
		if payload.Type == layers.DNSTypeOPT || payload.Type == layers.DNSTypeSOA {
			continue
		}
		exclude_tld := strings.Split(string(payload.Name), ".")
		if len(exclude_tld) > 2 {
			feature.PeriodsInSubDomain = len(exclude_tld) - 2 // the kernel wount allow tld to be redirected to user space
			mx_len, totalLen, _ := LongestandTotoalLenSubdomains(exclude_tld[:len(exclude_tld)-2])
			feature.LongestLabelDomain = mx_len
			feature.TotalCharsInSubdomain = totalLen

			ucount, _, ncount := DomainVarsCount(strings.Join(exclude_tld[:len(exclude_tld)-2], ""))

			feature.UCaseCount = ucount
			feature.NumberCount = ncount
			feature.Tld = strings.Join(exclude_tld[len(exclude_tld)-2:], ".")

			feature.IsEgress = isEgress

			feature.Fqdn = string(payload.Name)

			feature.Entropy = Entropy(exclude_tld[:len(exclude_tld)-2])
			feature.RecordType = payload.Type.String()

			features = append(features, feature)
			mrsh, _ := json.Marshal(feature)

			if utils.DEBUG {
				fmt.Println(string(mrsh))
			}
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
		features = make([]DNSFeatures, 0)
	}

	if len(dns_packet.Questions) > 0 && isEgress {
		features, _ = ParseDnsQuestions(dns_packet, features, isEgress, i)
		i += len(features)
	}

	if len(dns_packet.Answers) > 0 && isIngress {
		features, _ = ParseDnsAnswers(dns_packet, features, isEgress)
	}

	// used for mdns and edns based parsing when addon dns querstios are passed
	//  the malware can send more malicious information in the addon section to bypass detection
	if len(dns_packet.Additionals) > 0 && (isIngress || isEgress) && false {
		features, _ = ParseDnsAdditional(dns_packet, features, isEgress)
	}

	if len(dns_packet.Authorities) > 0 && isEgress && false {
		features, _ = ParseDnsAuth(dns_packet, features, isEgress)
	}

	if !utils.DEBUG && isEgress {
		log.Println("[x] Total Raw Process Features extracetd for the DNS Packet is ", len(features))
		for _, feature := range features {
			mrsh, _ := json.Marshal(feature)
			fmt.Println(string(mrsh))
		}
	}

	return features, nil
}
