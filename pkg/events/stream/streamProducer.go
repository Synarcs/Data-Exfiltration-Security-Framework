package stream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/segmentio/kafka-go"
)

const (
	KAFKA_BROKER_CONN_TIMEOUT = time.Second * 2
	KAFKA_BROKER_CTX_TIMEOUT  = time.Second * 2
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

	connContext, _ := context.WithTimeout(ctx, KAFKA_BROKER_CTX_TIMEOUT)
	connErrorChan := make(chan error)
	connDone := make(chan bool)

	prod.Writer = &kafka.Writer{
		Addr:         kafka.TCP(prod.KafkaBrokerConfig.Brokers...),
		Topic:        STREAM_THREAT_TOPIC,
		Balancer:     &kafka.RoundRobin{},
		BatchSize:    1,
		RequiredAcks: kafka.RequireOne,
		Async:        true,
		Transport: &kafka.Transport{
			DialTimeout: KAFKA_BROKER_CONN_TIMEOUT,
		},
	}

	go func(erroChan chan error, connDone chan bool) {
		// dial to kraft enbaled leader kafka broker
		connLeader, err := kafka.Dial("tcp", net.JoinHostPort(prod.KafkaBrokerConfig.GlobalConfig.StreamServers.Ip,
			prod.KafkaBrokerConfig.GlobalConfig.StreamServers.Port))

		if err != nil {
			erroChan <- err
			return
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
				utils.Logger.Printf("Topic already exists %+v", err)
			}
			erroChan <- err
		}

		connDone <- true
	}(connErrorChan, connDone)

	for {
		select {
		case <-connContext.Done():
			// channel is closed to ensure there is a timeout connect to remote kafka broker, since the kafka uses background context blocking node agent
			utils.Log("Error connecting to the remote Kafka broker ", connContext.Err())
			return nil
		case err := <-connErrorChan:
			if connContext.Err(); err != nil {
				// there is other error before the connection context with timeout has closed
				utils.Log("Error connecting to remote kafka broker ", err.Error())
			}
			close(connErrorChan)
			return err
		case <-connDone:
			utils.Log("Connected to remote kafka broker ", prod.KafkaBrokerConfig.Brokers)
			close(connDone)
			return nil
		default:
			utils.Log("Trying to connect to remote Kafka broker ...", prod.KafkaBrokerConfig.Brokers)
			time.Sleep(time.Second)
		}
	}
}

func (prod *StreamProducer) StreamThreadEvent(event []byte) error {
	if prod.Writer == nil {
		return fmt.Errorf("kafka writer not initialized")
	}

	utils.Log("Publishing  to remote kafka broker ", prod.Writer.Addr.Network(), prod.Writer.Addr.String())

	if err := prod.Writer.WriteMessages(context.Background(), kafka.Message{
		Value: event,
		Time:  time.Now(),
	}); err != nil {
		if !utils.DEBUG {
			utils.Log("Error writing to kafka ", err)
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

	if utils.DEBUG {
		utils.Log("Event Size (bytes):", len(marshalledEvent))
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
		return nil
	}

	if err := prod.conn.Close(); err != nil {
		return err
	}

	return nil
}
