package events

import (
	"context"
	"encoding/json"
	"log"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/segmentio/kafka-go"
)

type StreamConsumer struct {
	StreamBrokerConfig
	Consumer *kafka.Reader
}

func (k *StreamConsumer) ConsumeStreamAnalyzedThreatEvent(ctx context.Context) error {

	streamReader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: k.Brokers,
		Topic:   k.Topic,
	})

	k.Consumer = streamReader
	for {
		msg, err := streamReader.ReadMessage(ctx)
		if err != nil {
			if utils.DEBUG {
				log.Printf("Error reading message for remote kafka broker %+v", err)
			}
		}

		// the remote kafka stream analytics will always use kafka streams for extreme enhanced streme analytics
		var statefulAnalyzedStreeamEvent RemoteStreamInferenceAnalyzed

		if err := json.Unmarshal(msg.Value, statefulAnalyzedStreeamEvent); err != nil {
			log.Printf("Erroring unmarshall the remote stream analyzed event %+v", err)
			return err
		}

		if egress := utils.GetKeyPresentInCache(statefulAnalyzedStreeamEvent.Tld); !egress {
			utils.UpdateDomainBlacklistInCache(statefulAnalyzedStreeamEvent.Tld, statefulAnalyzedStreeamEvent.Fqdn)
		}

		if ingress := utils.IngGetKeyPresentInCache(statefulAnalyzedStreeamEvent.Tld); !ingress {
			utils.IngUpdateDomainBlacklistInCache(statefulAnalyzedStreeamEvent.Tld)
		}

	}
}
