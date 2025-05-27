/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
*/

package com.synarcs.controller.config.yaml.k8s;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CloudOrchestration {

    private boolean isEnabled;
    private String k8sAdvertisedHostServiceAddress;

    private CniConfig cni;
}
