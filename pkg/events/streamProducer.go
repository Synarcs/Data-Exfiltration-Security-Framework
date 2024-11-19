package events

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/segmentio/kafka-go"
)

type StreamBrokerConfig struct {
	Brokers []string
	Topic   string
}

type StreaClient struct {
	StreamBrokerConfig
	conn *kafka.Conn
}

const (
	STREAM_THREAT_TOPIC = "exfil-sec"
)

func (stream *StreaClient) GenerateStreamKafkaProducer(ctx *context.Context) error {

	conn, err := kafka.Dial("tcp", "10.0.0.175:9092")

	if err != nil {
		log.Printf("Error connecting to remote stream client, node daemon booted without it .. %+v", err)
		return err
	}

	controller, err := conn.Controller()
	if err != nil {
		panic(err.Error())
	}

	connLeader, err := kafka.DialLeader(*ctx, "tcp", net.JoinHostPort(controller.Host, strconv.Itoa(controller.Port)), STREAM_THREAT_TOPIC, 0)

	if err != nil {
		panic(err.Error())
	}
	stream.conn = connLeader
	return nil
}

func (stream *StreaClient) StreamThreadEvent(event []byte) error {
	if stream.conn == nil {
		return nil
	}
	stream.conn.SetReadDeadline(time.Now().Add(time.Second * 10))

	_, err := stream.conn.WriteMessages(
		kafka.Message{
			Value: event,
		},
	)
	if err != nil {
		return err
	}
	return nil
}

func (stream *StreaClient) MarshallThreadEvent(event interface{}) error {
	marshalledEvent, err := json.Marshal(event)
	if err != nil {
		return err
	}

	if err := stream.StreamThreadEvent(marshalledEvent); err != nil {
		return err
	}

	return nil
}

func (stream *StreaClient) CloseStreamClient() error {
	if stream.conn == nil {
		return fmt.Errorf("The remote kafka broker conn is %+v", stream.conn)
	}
	if err := stream.conn.Close(); err != nil {
		return err
	}

	return nil
}
