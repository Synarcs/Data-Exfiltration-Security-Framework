package events

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/Data-Exfiltration-Security-Framework/pkg/utils"
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
	TotalChars            int
	TotalCharsInSubdomain int // holds the chars which are unicode encodable and can be stored
	NumberCount           int
	UCaseCount            int
	LCaseCount            int
	Entropy               float32
	PeriodsInSubDomain    int
	LongestLabelDomain    int
	AveerageLabelLength   float32
	IsEgress              bool
	AuthZoneSoaservers    map[string]string // zone master --> mx record type
}

type MaliciousDetectedUserSpaceCount int

type KernelPacketDropRedirectInterface interface {
	PacketDPIRedirectionCountEvent | PacketDPIKernelDropCountEvent | MaliciousDetectedUserSpaceCount
}

type RawDnsEvent struct {
	Fqdn string
	Tld  string
}

var (
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
			"Fqdn", "Tld", "TotalChars", "TotalCharsInSubdomain",
			"NumberCount", "UCaseCount", "LCaseCount", "Entropy",
			"PeriodsInSubDomain", "LongestLabelDomain",
			"AveerageLabelLength", "IsEgress",
		},
	)
	sniffedDnsEvent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "fqdn",
			Help: "the fqdns and tld information for dns event",
		},
		[]string{
			"fqdn", "tld", "time",
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
		sniffedDnsEvent)
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
			"fqdn": e.Fqdn,
			"tld":  e.Tld,
			"time": time.Now().GoString(),
		}).Set(1.21)
	default:
		return fmt.Errorf("unsupported event type: %T", e)
	}

	return nil
}

func ExportMaliciousEvents(feature DNSFeatures) error {
	if exportCount {
		malicious_detected_event_userspace.Inc()
	}
	maliciousdetectedDnsPacket.With(
		prometheus.Labels{
			"Fqdn":                  feature.Fqdn,
			"Tld":                   feature.Tld,
			"TotalChars":            strconv.Itoa(feature.TotalChars),
			"TotalCharsInSubdomain": strconv.Itoa(feature.TotalCharsInSubdomain),
			"NumberCount":           strconv.Itoa(feature.NumberCount),
			"UCaseCount":            strconv.Itoa(feature.UCaseCount),
			"LCaseCount":            strconv.Itoa(feature.LCaseCount),
			"Entropy":               strconv.FormatFloat(float64(feature.Entropy), 'f', -1, 64),
			"PeriodsInSubDomain":    strconv.Itoa(feature.PeriodsInSubDomain),
			"LongestLabelDomain":    strconv.Itoa(feature.LongestLabelDomain),
			"AveerageLabelLength":   strconv.FormatFloat(float64(feature.AveerageLabelLength), 'f', -1, 64),
			"IsEgress":              strconv.FormatBool(feature.IsEgress),
		},
	).Set(float64(feature.TotalChars))
	return nil
}
