package stream

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events/stream/actions"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/segmentio/kafka-go"
)

type StreamConsumer struct {
	KafkaBrokerConfig                   *StreamBrokerConfig
	Consumers                           map[string]*kafka.Reader
	EgresseBPFKernelTCCollection        *ebpf.Collection
	EgresseBPFKernelTCCollectionProgram *ebpf.Program
	TopDomainsCache                     *utils.TopDomains
	ConsumerErroChan                    chan error
	EventAckKernelFilter                *actions.EventAckKernelFilter
	L3NodeFilterCache                   *lru.Cache[string, uint32] // the cache is user space safes kernel bpf syscall and no need of locks in user space for concurrent reads from consumer
}

func (consumer *StreamConsumer) NewStreamAckEvents(iface *netinet.NetIface) {
	consumer.EventAckKernelFilter = &actions.EventAckKernelFilter{
		EgresseBPFKernelTCCollection:        consumer.EgresseBPFKernelTCCollection,
		EgresseBPFKernelTCCollectionProgram: consumer.EgresseBPFKernelTCCollectionProgram,
		NetIface:                            iface,
	}
}

func (consumer *StreamConsumer) InitLruUserSpaceL3Cache() error {
	// for performance and log for malicious l3 filter cache address
	cache, err := lru.New[string, uint32](1000)
	if err != nil {
		return err
	}
	consumer.L3NodeFilterCache = cache
	return nil
}

func (consumer *StreamConsumer) NewStreamKafkaConsumer(ctx context.Context) error {

	// all the malicious domains transfering over UDP to be blacklisted in local cache of LRU fo rnude agent
	streamReader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: consumer.KafkaBrokerConfig.Brokers,
		GroupID: "dataplane-controller-infer" + utils.GenerateUniqueConsumerGroupId(),
		Topic:   STREAM_THREAT_TOPIC_INFER,
	})

	// all the malicious domains transfering over TCP to be blacklisted in local cache of LRU fo rnude agent
	streamReaderTcpRecursorInfer := kafka.NewReader(kafka.ReaderConfig{
		Brokers: consumer.KafkaBrokerConfig.Brokers,
		GroupID: "dataplane-controller-infer-tcp" + utils.GenerateUniqueConsumerGroupId(),
		Topic:   STREAM_THREAT_TOPIC_INFER_TCP,
	})

	// process the topic which are meant for controller to update node agent caches for benign TLD domains
	streamReaderSldBenignTopic := kafka.NewReader(kafka.ReaderConfig{
		Brokers: consumer.KafkaBrokerConfig.Brokers,
		GroupID: "dataplane-controller-infer-sld-benign" + utils.GenerateUniqueConsumerGroupId(),
		Topic:   STREAM_BENIGN_SLD_TOPIC,
	})

	consumer.Consumers = make(map[string]*kafka.Reader)
	consumer.Consumers[STREAM_THREAT_TOPIC_INFER] = streamReader
	consumer.Consumers[STREAM_THREAT_TOPIC_INFER_TCP] = streamReaderTcpRecursorInfer
	consumer.Consumers[STREAM_BENIGN_SLD_TOPIC] = streamReaderSldBenignTopic
	consumer.ConsumerErroChan = make(chan error)

	if err := consumer.InitLruUserSpaceL3Cache(); err != nil {
		return err
	}
	return nil
}

// used as a bridge from controller provided l3 dynamic ipv4/ ipv6 addresses used to dynamically reconfigure eBPF maps in kernel to blacklist the l3 remote c2 servers
// Note the DGA domain mutation kernel will annyway prevent and control plane blacklist the domains on c2 servers as well as over the eBPF node agent LUR cache in user space andc kernel
// Controller also reprograms the data plane, to ensure any other protocols traffic to such remote ip's is blocked with controller dynamically resolving soch l3 ip addreses to kill any potential future breach attempts to these remote c2 server ip via different protocl
func (consumer *StreamConsumer) ConfigureeBPFEgressHandlerForDynamicL3Blacklist(ctx context.Context, tcCollection *ebpf.Collection, tcProgram *ebpf.Program, iface *netinet.NetIface) {
	// configure the injected eBPF egress program in kernel over TC
	consumer.EgresseBPFKernelTCCollection = tcCollection
	consumer.EgresseBPFKernelTCCollectionProgram = tcProgram
	consumer.NewStreamAckEvents(iface)
}

func (consumer *StreamConsumer) AddL3FilterForTrafficOverKernelTC(ctx context.Context, consumedeControllerEvent *events.RemoteStreamInferenceControllerAnalyzed) {
	configMapIpv4 := consumer.EgresseBPFKernelTCCollection.Maps[events.EXFIL_SECURITY_EGRESS_L3_IPV4_DYNAMIC_NETPOOL_C2_FILTER]
	// TODO Add support for ipv6 filter routing in kernel
	// configMapIpv6 := consumer.EgresseBPFKernelSockCollection.Maps[events.EXFIL_SECURITY_EGRESS_L3_IPV6_DYNAMIC_NETPOOL_C2_FILTER]

	if configMapIpv4 == nil {
		log.Println("Kernel is configured with l3 netpools for egress TC filter right now, please ensure L3 Netpool filter is enabled")
		return
	}

	// controller will always stream a valid ipv4, ipv6 l3 address to data plane
	for _, remoteIpAddressInferedMaliciousController := range consumedeControllerEvent.ResolveAddressMaliciousC2Domains {
		// convert to network order
		ipv4BigEndianAddress := utils.GenerateBigEndianIpv4(remoteIpAddressInferedMaliciousController)
		if _, fd := consumer.L3NodeFilterCache.Get(remoteIpAddressInferedMaliciousController); !fd {
			log.Println("Updating the malicious l3 filter in kernel ", utils.BigEndianToIPv4(ipv4BigEndianAddress))
			consumer.L3NodeFilterCache.Add(remoteIpAddressInferedMaliciousController, ipv4BigEndianAddress)
			if err := configMapIpv4.Update(ipv4BigEndianAddress, ipv4BigEndianAddress, ebpf.UpdateAny); err != nil {
				if !errors.Is(err, ebpf.ErrKeyExist) {
					log.Printf("Error while updating the malicious l3 filter in kernel %+v", err)
				}
			}
		}
	}
}

func (c *StreamConsumer) ConsumeStreamAnalyzedThreatEvent(ctx context.Context) error {
	for topic, consumer := range c.Consumers {
		if topic != STREAM_BENIGN_SLD_TOPIC && topic == STREAM_THREAT_TOPIC_INFER {
			go func(consumer *kafka.Reader, ctx context.Context) {
				for {
					if err := ctx.Err(); err != nil {
						if errors.Is(err, io.EOF) {
							time.Sleep(time.Second)
						} else {
							c.ConsumerErroChan <- err
							return
						}
					}
					msg, err := consumer.ReadMessage(ctx)
					if err != nil {
						c.ConsumerErroChan <- err
					}

					// the controller with use to write to a different topic which all nodes in data plane in same consumer group read and commits their offsets
					var statefulAnalyzedStreeamEvent events.RemoteStreamInferenceControllerAnalyzed

					if err := json.Unmarshal(msg.Value, &statefulAnalyzedStreeamEvent); err != nil {
						c.ConsumerErroChan <- err
					}

					if utils.DEBUG {
						log.Println("Consuming from the stream threat topic ", STREAM_THREAT_TOPIC_INFER)
						log.Println("Consumed thread event from other node or same data breach over DNS was prevented and C2 / tunnel impant was killed by node-agent over remote C2 Implant Server L3 IP",
							statefulAnalyzedStreeamEvent.DetectedThreadNodeIpv4, len(statefulAnalyzedStreeamEvent.ResolveAddressMaliciousC2Domains), statefulAnalyzedStreeamEvent.ResolveAddressMaliciousC2Domains)
					}

					if !statefulAnalyzedStreeamEvent.IsForcedUnblock {
						if egress := utils.GetKeyPresentInEgressCache(statefulAnalyzedStreeamEvent.Tld); !egress {
							utils.UpdateDomainBlacklistInEgressCache(statefulAnalyzedStreeamEvent.Tld, statefulAnalyzedStreeamEvent.Fqdn)
						}

						if ingress := utils.IngGetKeyPresentInCache(statefulAnalyzedStreeamEvent.Tld); !ingress {
							utils.IngUpdateDomainBlacklistInCache(statefulAnalyzedStreeamEvent.Tld)
						}
					} else {
						utils.DeleteDomainBlackListInEgressCache(statefulAnalyzedStreeamEvent.Tld, statefulAnalyzedStreeamEvent.Fqdn)
						utils.IngDeleteDomainBlackListInCache(statefulAnalyzedStreeamEvent.Tld)
					}

					// check for l3 filtering over malicious ipv4, ipv6 c2 tunnel server Ip's
					if utils.DEBUG {
						if len(statefulAnalyzedStreeamEvent.ResolveAddressMaliciousC2Domains) > 0 {
							// inject l3 address for remote c2 address to block packets for both egress and ingress TC, only inject if not running orchestrated workloads and for purely bare-metal environments
							for _, nodeAddress := range statefulAnalyzedStreeamEvent.ResolveAddressMaliciousC2Domains {
								if net.ParseIP(nodeAddress).To4() != nil {
									log.Println("Received a dynamic controller aware blacklist ipv4 l3 address to be injected for filtering from skb in tc egress and ingress", net.ParseIP(nodeAddress).To4().String())
								} else {
									if net.ParseIP(nodeAddress).To16() == nil {
										log.Println("The remote C2 server cannot be blacklisted since its neither a valid ipv4 or ipv6")
									}
								}
							}
						}
					}

					// dynamically blacklist l3 in kernel egress tc
					if topic == STREAM_THREAT_TOPIC_INFER_TCP || topic == STREAM_THREAT_TOPIC_INFER {
						c.AddL3FilterForTrafficOverKernelTC(ctx, &statefulAnalyzedStreeamEvent)
					}
				}
			}(consumer, ctx)
		} else {
			go func(consumer *kafka.Reader, ctx context.Context) error {
				// for all the benign domains
				for {
					if err := ctx.Err(); err != nil {
						return ctx.Err()
					}
					msg, err := consumer.ReadMessage(ctx)
					if err != nil {
						c.ConsumerErroChan <- err
					}
					var sldEvent events.RemoteSLDNodeCacheUpdate
					if err := json.Unmarshal(msg.Value, &sldEvent); err != nil {
						c.ConsumerErroChan <- err
					}

					c.TopDomainsCache.UpdateDomainDomainTLDCache(sldEvent.SLD)
					utils.IngDeleteDomainBlackListInCache(sldEvent.SLD)
					utils.DeleteAllBlacklistforSLDInEgressCache(sldEvent.SLD)
				}
			}(consumer, ctx)
		}
	}

	for err := range c.ConsumerErroChan {
		return err
	}
	return nil
}

func (c *StreamConsumer) CloseConsumer() error {
	for _, consumer := range c.Consumers {
		if consumer == nil {
			continue
		}
		if err := consumer.Close(); err != nil {
			log.Println("Error closing consumer ", err.Error())
		}
	}
	return nil
}
