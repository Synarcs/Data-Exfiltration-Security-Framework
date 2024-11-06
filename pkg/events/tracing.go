package events

import (
	"crypto/tls"
	"net/http"

	"github.com/Data-Exfiltration-Security-Framework/pkg/model"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// metrics export for the prometheus ebpf kernel node exporter from egress tc traffic layer

type PacketDPIRedirectionCountEvent struct {
	KernelRedirectPacketCount uint32
	EvenTime                  string
}

type PacketDPIKernelDropCount struct {
	KernelRedirectPacketCount uint32
	EvenTime                  string
}

type KernelPacketDropRedirectInterface interface {
	PacketDPIRedirectionCountEvent | PacketDPIKernelDropCount
}

func RegisterPrometheusEvents() error {

	return nil
}

func StartPrometheusMetricExporterServer() error {

	metricMux := http.NewServeMux()

	metricMux.Handle("/metrics", promhttp.Handler())

	server := http.Server{
		Addr:    ":3232",
		Handler: metricMux,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	server.ListenAndServe()
	return nil
}

func Init() {

}

func ExportPromeEbpfExporterEvents[T KernelPacketDropRedirectInterface](event T) error {
	return nil
}

func ExportPromeEbpfExporterEventsDnsmaliciousEvent(maliciousEvent model.DNSFeatures) error {
	// log.Println("Exporting the metric to prometheus ebpf exporter")

	return nil
}
