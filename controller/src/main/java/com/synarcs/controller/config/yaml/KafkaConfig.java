package com.synarcs.controller.config.yaml;

import java.io.Serializable;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
@AllArgsConstructor
public class KafkaConfig implements Serializable {
    private final String BrokerUrlIpv4;

    private final int BrokerPort;
    private final int SchemaRegistryPort;

    private final String STREAM_THREAT_TOPIC;

    private final String STREAM_THREAT_TOPIC_INFER_STATE;

    private final String consumerGroupName;
}
