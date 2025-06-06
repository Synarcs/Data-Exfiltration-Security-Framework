/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package com.synarcs.controller.config.yaml;

import com.synarcs.controller.config.yaml.k8s.CloudOrchestration;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

// all custom config for the controller to process enhance stream analytics 

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Config {
    private Controller controller;
    private KafkaBrokerConfig streamConfig;
    private CloudOrchestration k8s;
}
