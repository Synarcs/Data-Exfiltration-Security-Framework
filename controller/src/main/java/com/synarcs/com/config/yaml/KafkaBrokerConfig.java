package com.synarcs.com.config.yaml;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class KafkaBrokerConfig {
    private String host;
    private int brokerPort;
    private SchemaRegistryConfig schemaRegistry;

    private String streamThreatTopic;
    private String streamThreatTopicInferState;
    private String consumerGroupName;
}
