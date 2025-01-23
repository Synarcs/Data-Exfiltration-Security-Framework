package stream

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/segmentio/kafka-go"
)

type StreamConsumer struct {
	KafkaBrokerConfig *StreamBrokerConfig
	Consumer          *kafka.Reader
}

func (consumer *StreamConsumer) GenerateStreamKafkaConsumer(ctx context.Context) error {

	streamReader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: consumer.KafkaBrokerConfig.Brokers,
		Topic:   STREAM_THREAT_TOPIC_INFER,
	})
	consumer.Consumer = streamReader
	return nil
}

func (consumer *StreamConsumer) ConsumeStreamAnalyzedThreatEvent(ctx context.Context) error {

	for {
		msg, err := consumer.Consumer.ReadMessage(ctx)
		if err != nil {
			if utils.DEBUG {
				log.Printf("Error reading message for remote kafka broker %+v", err)
			}
		}

		// the remote kafka stream analytics will always use kafka streams for extreme enhanced streme analytics
		var statefulAnalyzedStreeamEvent events.RemoteStreamInferenceAnalyzed

		if err := json.Unmarshal(msg.Value, &statefulAnalyzedStreeamEvent); err != nil {
			log.Printf("Erroring unmarshall the remote stream analyzed event %+v", err)
			return err
		}

		if egress := utils.GetKeyPresentInEgressCache(statefulAnalyzedStreeamEvent.Tld); !egress {
			utils.UpdateDomainBlacklistInEgressCache(statefulAnalyzedStreeamEvent.Tld, statefulAnalyzedStreeamEvent.Fqdn)
		}

		if ingress := utils.IngGetKeyPresentInCache(statefulAnalyzedStreeamEvent.Tld); !ingress {
			utils.IngUpdateDomainBlacklistInCache(statefulAnalyzedStreeamEvent.Tld)
		}

	}
}

func (consumer *StreamConsumer) CloseConsumer() error {
	if consumer.Consumer == nil {
		return fmt.Errorf("Error the Stream Consumer not started")
	}
	consumer.Consumer.Close()
	return nil
}
