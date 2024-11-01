package events

// metrics export for the prometheus ebpf kernel node exporter from egress tc traffic layer

type Events[T any] interface {
}

func ExportPromeEbpfExporterEvents(metricTracingEvent Events[any]) error {
	// log.Println("Exporting the metric to prometheus ebpf exporter")
	return nil
}
