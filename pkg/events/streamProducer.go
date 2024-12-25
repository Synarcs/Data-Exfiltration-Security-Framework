package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/segmentio/kafka-go"
)

type StreamBrokerConfig struct {
	Brokers []string
	Topic   string
}

type StreamClient struct {
	StreamBrokerConfig
	conn         *kafka.Conn
	GlobalConfig *utils.NodeAgentConfig
	ctx          *context.Context
}

const (
	STREAM_THREAT_TOPIC = "exfil-sec"
)

func (stream *StreamClient) GenerateStreamKafkaProducer(ctx *context.Context) error {

	conn, err := kafka.Dial("tcp", fmt.Sprintf("%s:%s", stream.GlobalConfig.StreamServer.Host, stream.GlobalConfig.StreamServer.Port))

	if err != nil {
		log.Printf("Error connecting to remote stream client, node daemon booted without it .. %+v", err)
		return err
	}

	if err != nil {
		panic(err.Error())
	}

	// dial to kraft enbaled leader kafka broker
	connLeader, err := kafka.Dial("tcp", net.JoinHostPort(stream.GlobalConfig.StreamServer.Host, stream.GlobalConfig.StreamServer.Port))

	if err != nil {
		panic(err.Error())
	}
	stream.conn = connLeader

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

	log.Println("Connecting to remote kafka broker ", conn.RemoteAddr().String())

	stream.ctx = ctx
	return nil
}

func (stream *StreamClient) StreamThreadEvent(event []byte) error {
	if stream.conn == nil {
		return nil
	}

	log.Println("Remote host ", stream.GlobalConfig.StreamServer.Ip, stream.GlobalConfig.StreamServer.Port)

	w := &kafka.Writer{
		Addr:  kafka.TCP(net.JoinHostPort(stream.GlobalConfig.StreamServer.Host, stream.GlobalConfig.StreamServer.Port)),
		Topic: STREAM_THREAT_TOPIC,
	}

	defer w.Close()
	log.Println(w.Addr.Network(), w.Addr.String())
	if err := w.WriteMessages(context.Background(), kafka.Message{
		Value: event,
	}); err != nil {
		if utils.DEBUG {
			log.Println("Error writing to kafka ", err)
		}
		return err
	}
	return nil
}

func (stream *StreamClient) MarshallStreamThreadEvent(event interface{}) error {
	marshalledEvent, err := json.Marshal(event)
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
		return fmt.Errorf("The remote kafka broker conn is %+v", stream.conn)
	}
	if err := stream.conn.Close(); err != nil {
		return err
	}

	return nil
}
