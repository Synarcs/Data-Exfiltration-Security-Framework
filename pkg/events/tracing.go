package events

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/Data-Exfiltration-Security-Framework/pkg/model"
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

type KernelPacketDropRedirectInterface interface {
	PacketDPIRedirectionCountEvent | PacketDPIKernelDropCountEvent | model.DNSFeatures
}

type RawDnsEvent struct {
	Fqdn string
	Tld  string
}

var (
	drop_event_metric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kernel_packet_drop_event",
			Help: "The kernel packet drop  event",
		},
		[]string{"drop_count", "time"},
	)
	redirect_event_metric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kernel_packet_redirect_event",
			Help: "The kernel packet  redirect event",
		},
		[]string{"redirect_count", "time"},
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

func init() {
	prometheus.MustRegister(drop_event_metric,
		redirect_event_metric, maliciousdetectedDnsPacket,
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
	log.Println("debug callued for string prom metrics")
	switch e := any(event).(type) {
	case PacketDPIKernelDropCountEvent:
		// Handle drop count event
		drop_event_metric.With(
			prometheus.Labels{
				"drop_count": fmt.Sprintf("%d", e.KernelDropPacketCount),
				"time":       e.EvenTime,
			},
		).Set(float64(e.KernelDropPacketCount))
	case PacketDPIRedirectionCountEvent:
		// Handle redirection event
		redirect_event_metric.With(
			prometheus.Labels{
				"redirect_count": fmt.Sprintf("%d", e.KernelRedirectPacketCount),
				"time":           e.EvenTime,
			},
		).Set(float64(e.KernelRedirectPacketCount))
	case model.DNSFeatures:
		maliciousdetectedDnsPacket.With(
			prometheus.Labels{
				"Fqdn":                  e.Fqdn,
				"Tld":                   e.Tld,
				"TotalChars":            strconv.Itoa(e.TotalChars),
				"TotalCharsInSubdomain": strconv.Itoa(e.TotalCharsInSubdomain),
				"NumberCount":           strconv.Itoa(e.NumberCount),
				"UCaseCount":            strconv.Itoa(e.UCaseCount),
				"LCaseCount":            strconv.Itoa(e.LCaseCount),
				"Entropy":               strconv.Itoa(0),
				"PeriodsInSubDomain":    strconv.Itoa(e.PeriodsInSubDomain),
				"LongestLabelDomain":    strconv.Itoa(e.LongestLabelDomain),
				"AveerageLabelLength":   strconv.FormatFloat(float64(e.AveerageLabelLength), 'f', -1, 64),
				"IsEgress":              strconv.FormatBool(e.IsEgress),
			},
		).Set(float64(e.TotalChars))
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

func ExportPromeEbpfExporterEventsDnsmaliciousEvent(maliciousEvent model.DNSFeatures) error {
	// log.Println("Exporting the metric to prometheus ebpf exporter")

	return nil
}
