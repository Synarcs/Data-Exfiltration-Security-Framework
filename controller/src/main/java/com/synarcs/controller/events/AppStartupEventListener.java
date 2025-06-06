/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package com.synarcs.controller.events;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
public class AppStartupEventListener  {
    private Logger logger = LoggerFactory.getLogger(AppStartupEventListener.class);

    @EventListener(AppStartupEventListener.class)
    public void onAppStartup(ApplicationReadyEvent event) {
        logger.info("Controller booted successfully");
    }
}
