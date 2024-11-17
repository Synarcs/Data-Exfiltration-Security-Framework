package events

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/segmentio/kafka-go"
)

type StreamProducer struct {
	prodcuerr *kafka.Conn
}

const (
	STREAM_THREAT_TOPIC = "exfil-sec"
)

func (stream *StreamProducer) GenerateStreamKafkaProducer(ctx *context.Context) error {

	conn, err := kafka.Dial("tcp", "10.0.0.175:9092")

	if err != nil {
		panic(err.Error())
	}
	controller, err := conn.Controller()
	if err != nil {
		panic(err.Error())
	}

	connLeader, err := kafka.DialLeader(*ctx, "tcp", net.JoinHostPort(controller.Host, strconv.Itoa(controller.Port)), STREAM_THREAT_TOPIC, 0)

	if err != nil {
		panic(err.Error())
	}
	stream.prodcuerr = connLeader
	return nil
}

func (stream *StreamProducer) StreamThreadEvent(event []byte) error {
	stream.prodcuerr.SetReadDeadline(time.Now().Add(time.Second * 10))

	_, err := stream.prodcuerr.WriteMessages(
		kafka.Message{
			Value: event,
		},
	)
	if err != nil {
		return err
	}
	return nil
}

func (stream *StreamProducer) MarshallThreadEvent(event interface{}) error {
	marshalledEvent, err := json.Marshal(event)
	if err != nil {
		return err
	}

	if err := stream.StreamThreadEvent(marshalledEvent); err != nil {
		return err
	}

	return nil
}

func (stream *StreamProducer) CloseStreamClient() error {
	if stream.prodcuerr == nil {
		return fmt.Errorf("The remote kafka broker conn is %+v", stream.prodcuerr)
	}
	if err := stream.prodcuerr.Close(); err != nil {
		return err
	}

	return nil
}
