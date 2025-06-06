/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package com.synarcs.controller.config.yaml.k8s;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

// add the CNI config for the control plane to know the data plane node subset has k8s cni l3,l4,l7 filter support 

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CniConfig {
    
    private String name; // supported CNI name following OCI standards and kernel enforced l3, l4 filter policies
    private String l7FilterSupport; // envoy 
    private String l3FilterSupport;
}
