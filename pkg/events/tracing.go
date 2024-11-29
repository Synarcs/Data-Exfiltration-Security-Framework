package events

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// metrics export for the prometheus ebpf kernel node exporter from egress tc traffic layer

type PacketDPIRedirectionCountEvent struct {
	KernelRedirectPacketCount uint32
	EvenTime                  string
}

type PacketDPIKernelDropCountEvent struct {
	KernelDropPacketCount uint32
	EvenTime              string
}

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

// malicious_non_stanard_socket_port_transfer
type Malicious_Non_Stanard_Transfer struct {
	Src_port       int
	Dest_port      int
	IsUDPTransport bool
}

type MaliciousDetectedUserSpaceCount int
type Protocol string

const (
	DNS  Protocol = "DNS"
	ICMP Protocol = "ICMP"
	HTTP Protocol = "HTTP"
	SMTP Protocol = "SMTP"
)

type KernelPacketDropRedirectInterface interface {
	PacketDPIRedirectionCountEvent | PacketDPIKernelDropCountEvent |
		MaliciousDetectedUserSpaceCount | KernelNetlinkSocket | RawDnsEvent | Malicious_Non_Stanard_Transfer
}

type RawDnsEvent struct {
	Fqdn     string
	Tld      string
	IsEgress bool
	Protocol Protocol
}

type KernelNetlinkSocket struct {
	ProcessId     uint32
	Uid           uint32
	GroupId       uint32
	ThreadGroupId uint32
	ProcessInfo   [200]byte
}

var (
	// round trip latency effect for benigh traffic interaction from kernel to user space
	dnsRoundTripTime_metric = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "dns_round_trip_seconds",
			Help:    "DNS query round-trip time in seconds",
			Buckets: []float64{.1, .2, .4, .6, .8, 1, 2},
		},
	)

	drop_event_metric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kernel_packet_drop_event",
			Help: "The kernel packet drop event",
		},
		[]string{"drop_count", "time"},
	)
	drop_event_metric_count = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kernel_packet_drop_event_count",
			Help: "The kernel packet drop event",
		},
		// []string{"drop_count", "time"},
	)
	redirect_event_metric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kernel_packet_redirect_event",
			Help: "The kernel packet  redirect event",
		},
		[]string{"redirect_count", "time"},
	)

	redirect_event_metric_count = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kernel_packet_redirect_event_count",
			Help: "The kernel packet  redirect event",
		},
	)

	malicious_detected_event_userspace = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "malicious_detected_event_userspace",
			Help: "The malicious detected event count",
		},
	)

	maliciousdetectedDnsPacket = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "malicious_detected_dns_packet",
			Help: "The malicious detected dns packet",
		},
		[]string{
			"Fqdn", "Tld", "Subdomain", "TotalChars", "TotalCharsInSubdomain",
			"NumberCount", "UCaseCount", "Entropy", "Periods",
			"PeriodsInSubDomain", "LongestLabelDomain",
			"AverageLabelLength", "IsEgress", "RecordType", "AuthZoneSoaservers", "PhysicalNodeIpv4",
			"Protocol", "ExfilPort",
		},
	)
	// dns event for bengin traffic transfer
	sniffedDnsEvent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dns_traffic_metric_event",
			Help: "the fqdns and tld information for dns event",
		},
		[]string{
			"fqdn", "tld", "time", "isEgress", "protocol",
		},
	)

	malicious_tunnel_socket = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "malicious_tunnel_socket_net_device",
			Help: "the malicious tunnel socket net device",
		}, []string{
			"process_id",
			"user_id",
			"group_id",
			"threat_group_id",
			"prog_name",
		},
	)

	malicious_non_stanard_socket_port_transfer = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "malicious_non_stanard_socket_port_transfer",
			Help: "Detected packet transfer over a non standard DNS port overlay over UDP / TCP",
		}, []string{
			"src_port",
			"dest_port",
			"isUDPTransport",
		},
	)
)

const (
	exportCount bool = true
)

func init() {
	prometheus.MustRegister(drop_event_metric, drop_event_metric_count,
		redirect_event_metric, redirect_event_metric_count,
		maliciousdetectedDnsPacket, malicious_detected_event_userspace,
		sniffedDnsEvent, dnsRoundTripTime_metric,
		malicious_tunnel_socket, malicious_non_stanard_socket_port_transfer)
}

func StartPrometheusMetricExporterServer() error {

	log.Println("Starting the prometheus eBPF Node Agent metric exporter server on /metrics", 3232)
	metricMux := http.NewServeMux()

	metricMux.Handle("/metrics", promhttp.Handler())

	server := http.Server{
		Addr:    fmt.Sprintf(":%d", utils.PROMETHEUS_METRICS_PORT),
		Handler: metricMux,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, "metrics_time", time.Now().GoString())
		},
	}
	if err := server.ListenAndServe(); err != nil {
		log.Println("error starting the prometheus exporter server", err)
		return err
	}
	return nil
}

func ExportPromeEbpfExporterEvents[T KernelPacketDropRedirectInterface](event T) error {
	switch e := any(event).(type) {
	case PacketDPIKernelDropCountEvent:
		// Handle drop count event
		if exportCount {
			drop_event_metric_count.Inc()
		}
		drop_event_metric.With(
			prometheus.Labels{
				"drop_count": fmt.Sprintf("%d", e.KernelDropPacketCount),
				"time":       e.EvenTime,
			},
		).Set(float64(e.KernelDropPacketCount))
	case PacketDPIRedirectionCountEvent:
		// Handle redirection event
		if exportCount {
			redirect_event_metric_count.Inc()
		}
		redirect_event_metric.With(
			prometheus.Labels{
				"redirect_count": fmt.Sprintf("%d", e.KernelRedirectPacketCount),
				"time":           e.EvenTime,
			},
		).Set(float64(e.KernelRedirectPacketCount))

	case RawDnsEvent:
		sniffedDnsEvent.With(prometheus.Labels{
			"fqdn":     e.Fqdn,
			"tld":      e.Tld,
			"time":     time.Now().GoString(),
			"isEgress": strconv.FormatBool(e.IsEgress),
			"protocol": string(e.Protocol),
		}).Set(float64(time.Now().Unix()))

	case KernelNetlinkSocket:
		malicious_tunnel_socket.With(prometheus.Labels{
			"process_id":      strconv.Itoa(int(e.ProcessId)),
			"user_id":         strconv.Itoa(int(e.Uid)),
			"group_id":        strconv.Itoa(int(e.GroupId)),
			"threat_group_id": strconv.Itoa(int(e.ThreadGroupId)),
			"prog_name":       string(e.ProcessInfo[:]),
		}).Set(float64(time.Now().Unix()))
		return nil

	case Malicious_Non_Stanard_Transfer:
		malicious_non_stanard_socket_port_transfer.With(prometheus.Labels{
			"src_port":       strconv.Itoa(e.Src_port),
			"dest_port":      strconv.Itoa(e.Dest_port),
			"isUDPTransport": strconv.FormatBool(e.IsUDPTransport),
		}).Set(float64(e.Dest_port))
		return nil
	default:
		return fmt.Errorf("unsupported event type: %T", e)
	}

	return nil
}

func SanatizeRune(value []byte) string {
	if utf8.Valid(value) {
		return string(value)
	}
	var buffer bytes.Buffer
	for len(value) > 0 {
		r, size := utf8.DecodeRune(value)
		if r == utf8.RuneError && size == 1 {
			buffer.WriteString(fmt.Sprintf("\\x%02x", value[0]))
			value = value[1:]
		} else {
			buffer.WriteRune(r)
			value = value[size:]
		}
	}
	return buffer.String()
}

func ExportMaliciousEvents[T Protocol](feature DNSFeatures, nodeIp *net.IP, protocol T,
	exfilPort int) error {
	if exportCount {
		malicious_detected_event_userspace.Inc()
	}

	labels := prometheus.Labels{
		"Fqdn":                  SanatizeRune([]byte(feature.Fqdn)),
		"Tld":                   SanatizeRune([]byte(feature.Tld)),
		"Subdomain":             SanatizeRune([]byte(feature.Subdomain)),
		"TotalChars":            strconv.Itoa(feature.TotalChars),
		"TotalCharsInSubdomain": strconv.Itoa(feature.TotalCharsInSubdomain),
		"NumberCount":           strconv.Itoa(feature.NumberCount),
		"UCaseCount":            strconv.Itoa(feature.UCaseCount),
		"Entropy":               strconv.FormatFloat(float64(feature.Entropy), 'f', -1, 64),
		"Periods":               strconv.Itoa(feature.Periods),
		"PeriodsInSubDomain":    strconv.Itoa(feature.PeriodsInSubDomain),
		"LongestLabelDomain":    strconv.Itoa(feature.LongestLabelDomain),
		"AverageLabelLength":    strconv.FormatFloat(float64(feature.AverageLabelLength), 'f', -1, 64),
		"IsEgress":              strconv.FormatBool(feature.IsEgress),
		"RecordType":            feature.RecordType,
		"Protocol":              "DNS",
	}
	if feature.AuthZoneSoaservers == nil {
		labels["AuthZoneSoaservers"] = ""
	} else {
		labels["AuthZoneSoaservers"] = fmt.Sprintf("%s", feature.AuthZoneSoaservers)
	}

	if nodeIp != nil {
		labels["PhysicalNodeIpv4"] = nodeIp.String()
	} else {
		labels["PhysicalNodeIpv4"] = "" // error in local service lookup for ipv4 vnet lookup
	}

	labels["ExfilPort"] = strconv.Itoa(exfilPort)

	switch protocol {
	case T(DNS):
		labels["Protocol"] = string(DNS)
	case T(ICMP):
		labels["Protocol"] = string(ICMP)
	case T(SMTP):
		labels["Protocol"] = string(SMTP)
	case T(HTTP):
		labels["Protocol"] = string(HTTP)
	default:
		labels["Protocol"] = string("")
	}

	maliciousdetectedDnsPacket.With(
		labels,
	).Set(float64(feature.Entropy))
	return nil
}

func UpdateLatencyMetricEvents(roundProcessTime float64) {
	dnsRoundTripTime_metric.Observe(roundProcessTime / 1000.0)
}
