package events

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

type StreamBrokerConfig struct {
	Brokers []string
}

type StreamClient struct {
	StreamBrokerConfig
	conn         *kafka.Conn
	GlobalConfig *utils.NodeAgentConfig
	ctx          *context.Context
	Writer       *kafka.Writer
}

type HostNetworkExfilFeatures struct {
	ExfilPort        string
	Protocol         string
	PhysicalNodeIpv4 string
	PhysicalNodeIpv6 string
}

func (stream *StreamClient) GenerateStreamKafkaProducer(ctx *context.Context) error {
	brokerAddress := fmt.Sprintf("%s:%s", stream.GlobalConfig.StreamServer.Ip, stream.GlobalConfig.StreamServer.Port)

	stream.Writer = &kafka.Writer{
		Addr:         kafka.TCP(brokerAddress),
		Topic:        utils.STREAM_THREAT_TOPIC,
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
	connLeader, err := kafka.Dial("tcp", net.JoinHostPort(stream.GlobalConfig.StreamServer.Host, stream.GlobalConfig.StreamServer.Port))

	if err != nil {
		log.Printf("Error connecting to remote stream client, node daemon booted without it .. %+v", err)
		return err
	}
	stream.conn = connLeader

	topic := []kafka.TopicConfig{
		{
			Topic:             utils.STREAM_THREAT_TOPIC,
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

	stream.ctx = ctx
	return nil
}

func (stream *StreamClient) StreamThreadEvent(event []byte) error {
	if stream.Writer == nil {
		return fmt.Errorf("kafka writer not initialized")
	}

	log.Println("Publishing  to remote kafka broker ", stream.Writer.Addr.Network(), stream.Writer.Addr.String())

	if err := stream.Writer.WriteMessages(context.Background(), kafka.Message{
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

func (stream *StreamClient) MarshallStreamThreadEvent(event interface{}, networkConfig HostNetworkExfilFeatures) error {

	marshalledEvent, err := json.Marshal(StreamOrderMergedEvent(event, networkConfig))
	if err != nil {
		return err
	}

	if err := stream.StreamThreadEvent(marshalledEvent); err != nil {
		return err
	}

	return nil
}

func (stream *StreamClient) CloseStreamClient() error {
	if stream.conn == nil {
		return fmt.Errorf("The kafka conn client is not initialized cannot close a non-existant open connection ....")
	}
	
	if stream.Writer == nil {
		return fmt.Errorf("kafka writer not initialized")
	}

	if err := stream.conn.Close(); err != nil {
		return err
	}

	return nil
}
