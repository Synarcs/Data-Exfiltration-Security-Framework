package events

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/conf"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/shirou/gopsutil/v3/process"
)

// metrics export for the prometheus ebpf kernel node exporter from egress tc traffic layer

const (
	METRICS_EXPORTER_DEFAULT_PORT = 9092
)

type PacketDPIRedirectionCountEvent struct {
	KernelRedirectPacketCount uint32
	EvenTime                  string
}

type PacketDPICloneRedirectionCountEvent struct {
	KernelCloneRedirectPacketCount uint32
	EvenTime                       string
}

type PacketDPICloneRedirectionDropCountEvent struct {
	KernelCloneRedirectPacketDropCount uint32
	EvenTime                           string
}

type PacketDPIKernelDropCountEvent struct {
	KernelDropPacketCount uint32
	EvenTime              string
}

type MaliciousProcessAliveTime struct {
	ExfiltrationStartedAt string
	ProcessId             uint32
	AliveTime             int
}

type VxlanEncapKenrelEvent struct {
	Vni                   uint32
	Udp_src_port          uint16
	Udp_dst_port          uint16
	L3_tunnel_address     string
	L2_tunnel_mac_address string
	Domains               []string
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

type MaliciousDetectedUserSpaceCount int
type Protocol string

const (
	DNS  Protocol = "DNS"
	ICMP Protocol = "ICMP"
	HTTP Protocol = "HTTP"
	SMTP Protocol = "SMTP"
)

// TODO Make nested generic service interfaces
type KernelPacketDropRedirectInterface interface {
	PacketDPIRedirectionCountEvent | PacketDPIKernelDropCountEvent | PacketDPICloneRedirectionCountEvent | PacketDPICloneRedirectionDropCountEvent |
		MaliciousDetectedUserSpaceCount | KernelNetlinkSocket | RawDnsEvent | Malicious_Non_Stanard_Transfer | VxlanEncapKenrelEvent | MaliciousProcessAliveTime
}

// CPU and memory metrics for the process
var (
	// CPU and memory metrics for the process
	cpuUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "process_cpu_usage_percent",
			Help: "CPU usage percentage of the process",
		},
		[]string{"state"}, // "user", "system", "idle" 
	)

	// Memory usage gauge
	memoryUsageGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "process_memory_usage_bytes",
			Help: "Memory usage of the process in bytes",
		},
	)
)

// DNS security control metrics
var (
	// round trip latency effect for benigh traffic interaction from kernel to user space
	dnsRoundTripTime_metric = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "dns_round_trip_seconds",
			Help:    "DNS query round-trip time in seconds",
			Buckets: []float64{100, 200, 300, 400, 500, 900, 1200},
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

	// redirect for non standard DNS port transfer
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

	// clone redirect for non standard DNS port transfer
	clone_redirect_event_metric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kernel_packet_clone_redirect_event",
			Help: "Kernel packet clone redirect events for potential malicious exfiltration traffic over non-standard ports",
		},
		[]string{"clone_redirect_count", "time"},
	)

	// out of all the clone redirected packets denotes how many of them where actually dropped from kernel
	clone_redirect_event_metric_count = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kernel_packet_clone_redirect_event_count",
			Help: "Total count of kernel packet clone redirect events for potential malicious exfiltration traffic over non-standard ports",
		},
	)

	clone_redirect_event_drop_metric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kernel_packet_clone_redirect_drop_event",
			Help: "Kernel packet clone redirect drop events for potential malicious exfiltration traffic over non-standard ports",
		},
		[]string{"clone_redirect_drop_count", "time"},
	)

	clone_redirect_event_drop_metric_count = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kernel_packet_clone_redirect_drop_count",
			Help: "Total count of malicious packets dropped after clone redirect and deep analysis",
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
			"Fqdn", "SLD", "Subdomain", "TotalChars", "TotalCharsInSubdomain",
			"NumberCount", "UCaseCount", "Entropy", "Periods",
			"PeriodsInSubDomain", "LongestLabelDomain",
			"AverageLabelLength", "IsEgress", "RecordType", "AuthZoneSoaservers", "PhysicalNodeIpv4",
			"Protocol", "ExfilPort", "ProcessId",
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

	malicious_process_alive_system = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "malicious_process_alive_system",
			Help: "Time the malicious process was alive in system before terminated by node-agent",
		}, []string{
			"Exfiltration_Attempt_Started_At",
			"Process_Id",
			"Alive_Time",
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

	malicious_vxlan_encap_dns_vtep_tunnel_transfer = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "malicious_vxlan_encap_dns_vtep_tunnel_transfer",
			Help: "Detected packet transfer over a non standard DNS port overlay over UDP / TCP",
		}, []string{
			"vni",
			"udp_src_port", // l4 overlay ports for vxlan encap vial link with  virtual mac
			"udp_dst_port",
			"l3_tunnel_address",     // l3 tunnel address for remote tunnel not the host bridge
			"l2_tunnel_mac_address", // l2 tunnel mac address for the vtep on the host
			"domains",
		},
	)
)

const (
	exportCount bool = true
)

func init() {
	prometheus.MustRegister(drop_event_metric, drop_event_metric_count,
		redirect_event_metric, redirect_event_metric_count,
		clone_redirect_event_metric, clone_redirect_event_metric_count,
		clone_redirect_event_drop_metric, clone_redirect_event_drop_metric_count,
		maliciousdetectedDnsPacket, malicious_detected_event_userspace, malicious_process_alive_system,
		sniffedDnsEvent, dnsRoundTripTime_metric,
		malicious_tunnel_socket, malicious_non_stanard_socket_port_transfer,
		malicious_vxlan_encap_dns_vtep_tunnel_transfer, cpuUsage, memoryUsageGauge)
}

func ExportCpuProcessMetrics(ctx context.Context) error {
	pid := os.Getpid()
	cpuCount := float64(runtime.NumCPU())
	exportCpumemMetrics := func() error {
		proc, err := process.NewProcess(int32(pid))

		if err != nil {
			return err
		}

		cpuPercent, _ := proc.Percent(time.Second)

		memUsage, _ := proc.MemoryInfo()

		cpuPercent = cpuPercent / cpuCount
		idlePercent := 100.0 - cpuPercent

		cpuUsage.WithLabelValues("idle").Set(idlePercent)
		cpuUsage.WithLabelValues("load").Set(cpuPercent)

		memoryUsageGauge.Set(float64(memUsage.RSS))

		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			if err := exportCpumemMetrics(); err != nil {
				utils.Log(err.Error())
			}
			time.Sleep(time.Second)
		}
	}
}

func StartPrometheusMetricExporterServer(config *conf.NodeAgentConfig) error {

	var metricsExporterPort int
	if config == nil {
		metricsExporterPort = METRICS_EXPORTER_DEFAULT_PORT
	} else {
		metricsExporterPort, _ = strconv.Atoi(config.MetricsExporter.Port)
	}

	utils.Log("Starting the prometheus eBPF Node Agent metric exporter server on /metrics", metricsExporterPort)

	metricMux := http.NewServeMux()

	metricMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	metricMux.Handle("/metrics", promhttp.Handler())

	server := http.Server{
		Addr:    fmt.Sprintf(":%d", metricsExporterPort),
		Handler: metricMux,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, "metrics_time", time.Now().GoString())
		},
	}

	if err := server.ListenAndServe(); err != nil {
		utils.Log("error starting the prometheus exporter server", err)
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

	case PacketDPICloneRedirectionCountEvent:
		if exportCount {
			clone_redirect_event_metric_count.Inc()
		}

		clone_redirect_event_metric.With(
			prometheus.Labels{
				"clone_redirect_count": fmt.Sprintf("%d", e.KernelCloneRedirectPacketCount),
				"time":                 e.EvenTime,
			},
		).Set(float64(e.KernelCloneRedirectPacketCount))

	case PacketDPICloneRedirectionDropCountEvent:
		if exportCount {
			clone_redirect_event_drop_metric_count.Inc()
		}
		clone_redirect_event_drop_metric.With(
			prometheus.Labels{
				"clone_redirect_drop_count": fmt.Sprintf("%d", e.KernelCloneRedirectPacketDropCount),
				"time":                      e.EvenTime,
			},
		).Set(float64(e.KernelCloneRedirectPacketDropCount))

	case RawDnsEvent:
		sniffedDnsEvent.With(prometheus.Labels{
			"fqdn":     e.Fqdn,
			"tld":      e.Tld,
			"time":     time.Now().GoString(),
			"isEgress": strconv.FormatBool(e.IsEgress),
			"protocol": string(e.Protocol),
		}).Set(float64(time.Now().Unix()))

	case KernelNetlinkSocket:
		if exportCount {
			malicious_detected_event_userspace.Inc()
		}
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

	case VxlanEncapKenrelEvent:
		malicious_vxlan_encap_dns_vtep_tunnel_transfer.With(prometheus.Labels{
			"vni":                   strconv.Itoa(int(e.Vni)),
			"udp_src_port":          strconv.Itoa(int(e.Udp_dst_port)),
			"udp_dst_port":          strconv.Itoa(int(e.Udp_dst_port)),
			"l3_tunnel_address":     e.L3_tunnel_address,
			"l2_tunnel_mac_address": e.L2_tunnel_mac_address,
			"domains":               strings.Join(e.Domains, ","),
		}).Set(float64(time.Now().Nanosecond()))
		return nil

	case MaliciousProcessAliveTime:
		malicious_process_alive_system.With(prometheus.Labels{
			"Exfiltration_Attempt_Started_At": e.ExfiltrationStartedAt,
			"Process_Id":                      strconv.Itoa(int(e.ProcessId)),
			"Alive_Time":                      strconv.Itoa(int(e.AliveTime)),
		})
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
	exfilPort int, procInfo *utils.MaliciousKernelTaskCommExportedProcInfo) error {
	if exportCount {
		malicious_detected_event_userspace.Inc()
	}

	labels := prometheus.Labels{
		"Fqdn":                  SanatizeRune([]byte(feature.Fqdn)),
		"SLD":                   SanatizeRune([]byte(feature.Tld)),
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

	// the kernel tc filter layer provides this to user space via task comm shared with user space via maps or ring buffers
	if procInfo != nil {
		labels["ProcessId"] = strconv.Itoa(int(procInfo.ProcessId))
	} else {
		labels["ProcessId"] = "Nan"
	}

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
