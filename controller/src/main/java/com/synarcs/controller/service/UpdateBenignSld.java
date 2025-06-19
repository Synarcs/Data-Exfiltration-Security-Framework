/* 
    Copyright (c) 2024–2025 Synarcs. All rights reserved.
*/
package com.synarcs.controller.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import com.synarcs.controller.config.ControllerKafkaTopics;
import com.synarcs.controller.config.yaml.Config;
import com.synarcs.controller.exceptions.MalformedDomainException;
import com.synarcs.controller.streamserdes.DnsdataplaneBenignSld;
import com.synarcs.controller.utils.DomainLexicalValidator;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class UpdateBenignSld {

    @Autowired
    private DomainLexicalValidator validator;

    private Config controllerConfig;

    @Autowired
    public UpdateBenignSld(Config config) {
        this.controllerConfig = config;
    }

    @Autowired
    private KafkaTemplate<String, Object> kafkaTemplate;

    public void sendDnsBenignDomainCacheUpdate(String benignSld) throws MalformedDomainException {
        log.info("Updating the benign domain cache of all nodes in dataplane");

        if (!validator.validateSld(benignSld)) 
            throw new MalformedDomainException("The domain SLD is not valid format " + benignSld);

        String[] labels = validator.getLabels(benignSld);
        kafkaTemplate.send(ControllerKafkaTopics.controllerInferenceBenignTopic, DnsdataplaneBenignSld.builder()
                        .sld(benignSld).tld(validator.getLabels(benignSld)[labels.length - 1]));
    } 
}


