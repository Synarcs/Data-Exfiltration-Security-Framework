package stream

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
	"github.com/segmentio/kafka-go"
)

type StreamConsumer struct {
	KafkaBrokerConfig                     *StreamBrokerConfig
	Consumers                             []*kafka.Reader
	EgresseBPFKernelSockCollection        *ebpf.Collection
	EgresseBPFKernelSockCollectionProgram *ebpf.Program
}

func (consumer *StreamConsumer) GenerateStreamKafkaConsumer(ctx context.Context) error {

	streamReader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: consumer.KafkaBrokerConfig.Brokers,
		Topic:   STREAM_THREAT_TOPIC_INFER,
	})
	streamReaderTcpRecursorInfer := kafka.NewReader(kafka.ReaderConfig{
		Brokers: consumer.KafkaBrokerConfig.Brokers,
		Topic:   STREAM_THREAT_TOPIC_INFER_TCP,
	})
	consumer.Consumers = []*kafka.Reader{
		streamReader, streamReaderTcpRecursorInfer,
	}
	return nil
}

// used as a bridge from controller provided l3 dynamic ipv4/ ipv6 addresses used to dynamically reconfigure eBPF maps in kernel to blacklist the l3 remote c2 servers
// Note the DGA domain mutation kernel will annyway prevent and control plane blacklist the domains on c2 servers as well as over the eBPF node agent LUR cache in user space andc kernel
// Controller also reprograms the data plane, to ensure any other protocols traffic to such remote ip's is blocked with controller dynamically resolving soch l3 ip addreses to kill any potential future breach attempts to these remote c2 server ip via different protocl
func (consumer *StreamConsumer) ConfigureeBPFEgressHandlerForDynamicL3Blacklist(ctx context.Context, tcCollection *ebpf.Collection, tcProgram *ebpf.Program) {
	// configure the injected eBPF egress program in kernel over TC
	consumer.EgresseBPFKernelSockCollection = tcCollection
	consumer.EgresseBPFKernelSockCollectionProgram = tcProgram
}

func (consumer *StreamConsumer) AddL3FilterForTraffic(ctx context.Context, consumedeControllerEvent *events.RemoteStreamInferenceControllerAnalyzed) error {
	configMapIpv4 := consumer.EgresseBPFKernelSockCollection.Maps[events.EXFIL_SECURITY_EGRESS_L3_IPV4_DYNAMIC_NETPOOL_C2_FILTER]
	configMapIpv6 := consumer.EgresseBPFKernelSockCollection.Maps[events.EXFIL_SECURITY_EGRESS_L3_IPV6_DYNAMIC_NETPOOL_C2_FILTER]

	if configMapIpv4 == nil || configMapIpv6 == nil {
		log.Println("Kernel is configured with l3 netpools for egress TC filter right now, please ensure L3 Netpool filter is enabled")
		return nil
	}

	for _, remoteIpAddressInferedMaliciousController := range consumedeControllerEvent.ResolveAddressMaliciousC2Domains {
		isIpv4 := net.IP(remoteIpAddressInferedMaliciousController).To4()
		if isIpv4 == nil {
			isIpv6 := net.IP(remoteIpAddressInferedMaliciousController).To16()
			if isIpv6 == nil {
				log.Println("Cannot blacklist in kernel eBPF since the rmmote c2 server does neither has correct Ipv4 and Ipv6 formatting")
				return nil
			}
			// TODO: Implement L3 filter for the kernel eBPF map for ipv6 address
			return nil
		}
		// convert to network order
		ipv4BigEndianAddress := utils.GenerateBigEndianIpv4(isIpv4.String())
		configMapIpv4.Put(ipv4BigEndianAddress, ipv4BigEndianAddress)
	}
	return nil
}

func (c *StreamConsumer) ConsumeStreamAnalyzedThreatEvent(ctx context.Context) error {
	errorChan := make(chan error)
	for _, consumer := range c.Consumers {
		go func(consumer *kafka.Reader, errorChan chan error) error {
			for {
				msg, err := consumer.ReadMessage(ctx)
				if err != nil {
					if utils.DEBUG {
						log.Printf("Error reading message for remote kafka broker %+v", err)
					}
					return err
				}

				// the controller with use to write to a different topic which all nodes in data plane in same consumer group read and commits their offsets
				var statefulAnalyzedStreeamEvent events.RemoteStreamInferenceControllerAnalyzed

				if err := json.Unmarshal(msg.Value, &statefulAnalyzedStreeamEvent); err != nil {
					log.Printf("Erroring unmarshall the remote stream analyzed event %+v", err)
					return err
				}

				log.Println("Consumed thread event from other node or same data breach over DNS was prevented and C2 / tunnel impant was killed by node-agent over remote C2 Implant Server L3 IP",
					statefulAnalyzedStreeamEvent.DetectedThreadNodeIpv4, statefulAnalyzedStreeamEvent.DetectedThreadNodeIpv6, statefulAnalyzedStreeamEvent.ResolveAddressMaliciousC2Domains)
				if egress := utils.GetKeyPresentInEgressCache(statefulAnalyzedStreeamEvent.Tld); !egress {
					utils.UpdateDomainBlacklistInEgressCache(statefulAnalyzedStreeamEvent.Tld, statefulAnalyzedStreeamEvent.Fqdn)
				}

				if ingress := utils.IngGetKeyPresentInCache(statefulAnalyzedStreeamEvent.Tld); !ingress {
					utils.IngUpdateDomainBlacklistInCache(statefulAnalyzedStreeamEvent.Tld)
				}

				if consumer.Config().Topic == STREAM_THREAT_TOPIC_INFER_TCP {
					c.AddL3FilterForTraffic(ctx, &statefulAnalyzedStreeamEvent)
				}
			}
		}(consumer, errorChan)
	}

	for {
		select {
		case err := <-errorChan:
			return fmt.Errorf(err.Error())
		}
	}
}

func (c *StreamConsumer) CloseConsumer() error {
	for _, consumer := range c.Consumers {
		if consumer == nil {
			continue
		}
		consumer.Close()
	}
	return nil
}
