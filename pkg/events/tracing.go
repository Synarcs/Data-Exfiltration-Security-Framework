package events

import "log"

// metrics export for the prometheus ebpf kernel node exporter from egress tc traffic layer

func ExportPromeEbpfExporterEvents(metricTracingEvent interface{}) error {
	log.Println("Exporting the metric to prometheus ebpf exporter")
	return nil
}
