/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package com.synarcs.controller;


public interface IController {
    void ConfigureKafkaBroker(String brokerUrl, int BrokerPort);
    void ProcessStreamAnalyticsDSl();
}
