package stream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"reflect"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/segmentio/kafka-go"
)

type StreamProducer struct {
	KafkaBrokerConfig *StreamBrokerConfig
	conn              *kafka.Conn
	Writer            *kafka.Writer
}

type HostNetworkExfilFeatures struct {
	ExfilPort        string
	Protocol         string
	PhysicalNodeIpv4 string
	PhysicalNodeIpv6 string
}

func (prod *StreamProducer) GenerateStreamKafkaProducer(ctx context.Context) error {

	prod.Writer = &kafka.Writer{
		Addr:         kafka.TCP(prod.KafkaBrokerConfig.Brokers...),
		Topic:        STREAM_THREAT_TOPIC,
		Balancer:     &kafka.LeastBytes{},
		BatchSize:    1,
		RequiredAcks: kafka.RequireAll,
		Async:        false,
		Transport: &kafka.Transport{
			DialTimeout: time.Second * 10,
			TLS:         nil,
		},
	}

	// dial to kraft enbaled leader kafka broker
	connLeader, err := kafka.Dial("tcp", net.JoinHostPort(prod.KafkaBrokerConfig.GlobalConfig.StreamServers.Ip,
		prod.KafkaBrokerConfig.GlobalConfig.StreamServers.Port))

	if err != nil {
		log.Printf("Error connecting to remote stream client, node daemon booted without it .. %+v", err)
		return err
	}
	prod.conn = connLeader

	topic := []kafka.TopicConfig{
		{
			Topic:             STREAM_THREAT_TOPIC,
			NumPartitions:     1,
			ReplicationFactor: 1,
		},
	}

	if err := connLeader.CreateTopics(topic...); err != nil {
		if errors.Is(err, kafka.TopicAlreadyExists) {
			log.Printf("Topic already exists %+v", err)
		}
		panic(err.Error())
	}

	return nil
}

func (prod *StreamProducer) StreamThreadEvent(event []byte) error {
	if prod.Writer == nil {
		return fmt.Errorf("kafka writer not initialized")
	}

	log.Println("Publishing  to remote kafka broker ", prod.Writer.Addr.Network(), prod.Writer.Addr.String())

	if err := prod.Writer.WriteMessages(context.Background(), kafka.Message{
		Value: event,
		Time:  time.Now(),
	}); err != nil {
		if !utils.DEBUG {
			log.Println("Error writing to kafka ", err)
		}
		return err
	}
	return nil
}

func StreamOrderMergedEvent(structs ...interface{}) map[string]interface{} {
	var streamEvent map[string]interface{} = make(map[string]interface{})

	for _, ss := range structs {
		v := reflect.ValueOf(ss)
		t := reflect.TypeOf(ss)

		for i := 0; i < v.NumField(); i++ {
			streamEvent[t.Field(i).Name] = v.Field(i).Interface()
		}
	}
	return streamEvent
}

func (prod *StreamProducer) MarshallStreamThreadEvent(event interface{}, networkConfig HostNetworkExfilFeatures) error {

	marshalledEvent, err := json.Marshal(StreamOrderMergedEvent(event, networkConfig))
	if err != nil {
		return err
	}

	if err := prod.StreamThreadEvent(marshalledEvent); err != nil {
		return err
	}

	return nil
}

func (prod *StreamProducer) CloseProducer() error {
	if prod.conn == nil {
		return fmt.Errorf("The kafka conn client is not initialized cannot close a non-existant open connection ....")
	}

	if prod.Writer == nil {
		return fmt.Errorf("kafka writer not initialized")
	}

	if err := prod.conn.Close(); err != nil {
		return err
	}

	return nil
}
