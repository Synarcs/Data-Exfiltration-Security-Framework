package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/Synarcs/DNSObelisk/controller/cni"
	"github.com/Synarcs/DNSObelisk/controller/conf"
	"github.com/segmentio/kafka-go"
)

type KafkaBrokersConfig struct {
	Brokers []string
}

type StreamConsumer struct {
	KafkaBrokerConfig *KafkaBrokersConfig
	Consumers         map[string]*kafka.Reader
}

func VerifyControllerSockHealthy() error {

	conn, err := net.Dial("tcp", "localhost:9000")
	if err != nil {
		return fmt.Errorf("the remote controller server needs to be healthy for Controller CNI socket to get config from %+v", err)
	}
	defer conn.Close()
	return nil
}

func InitControllerBrokerConfig() (*conf.GlobalControllerConfig, *StreamConsumer) {
	req, err := http.NewRequest("GET", "http://localhost:9000/config", nil)

	if err != nil {
		log.Printf("Error creating request: %v", err)
		return nil, nil
	}

	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		log.Printf("Error sending request: %v", err)
		return nil, nil
	}

	var config conf.GlobalControllerConfig

	configLoadedJsonReader := json.NewDecoder(resp.Body)
	if err := configLoadedJsonReader.Decode(&config); err != nil {
		log.Printf("Error decoding config from root controller: %v", err)
		return nil, nil
	}

	return &config, &StreamConsumer{
		KafkaBrokerConfig: &KafkaBrokersConfig{
			Brokers: []string{
				fmt.Sprintf("%s:%d", config.StreamConfig.Host, config.StreamConfig.BrokerPort),
			},
		},
		Consumers: make(map[string]*kafka.Reader),
	}
}

func (consumer *StreamConsumer) GenerateStreamKafkaConsumer(ctx context.Context) {
	streamReader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: consumer.KafkaBrokerConfig.Brokers,
		Topic:   STREAM_THREAT_TOPIC_INFER,
	})
	consumer.Consumers[STREAM_THREAT_TOPIC_INFER] = streamReader
}

func (consumer *StreamConsumer) ConsumeStreamControllerTopic(ctx context.Context, cniPolicyHandler cni.NetworkPolicies) error {
	if consumer.Consumers[STREAM_THREAT_TOPIC_INFER] == nil {
		return nil
	}
	log.Println("Started consuming events from the inferred controller sock for malicious domains to data plane ",
		STREAM_THREAT_TOPIC_INFER)
	for {
		if err := ctx.Err(); err != nil {
			return ctx.Err()
		}

		msg, err := consumer.Consumers[STREAM_THREAT_TOPIC_INFER].ReadMessage(ctx)

		if err != nil {
			return err
		}

		log.Println(msg)
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
