/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package com.synarcs.controller.config.yaml;

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
    private String recursorTCPTransportMaliciousTopic;
    private String consumerGroupName;
}
