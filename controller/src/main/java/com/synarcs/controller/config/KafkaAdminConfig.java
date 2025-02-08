package com.synarcs.controller.config;

import java.util.HashMap;
import java.util.Map;

import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.clients.admin.NewTopic;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.core.KafkaAdmin;

import com.synarcs.controller.config.yaml.Config;

@Configuration
public class KafkaAdminConfig {

    private Logger logger = LoggerFactory.getLogger(KafkaAdminConfig.class);
    private Config controllerConfig;
    
    @Autowired
    public KafkaAdminConfig(Config config) {
        this.controllerConfig = config;
    }

    @Bean
    public KafkaAdmin kafkaAdmin() {
        Map<String, Object> configs = new HashMap<>();
        configs.put(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, 
                controllerConfig.getStreamConfig().getHost()+":"+controllerConfig.getStreamConfig().getBrokerPort());
        return new KafkaAdmin(configs);
    }    

    @Bean
    public NewTopic inferenceControllerTopic() { 
        logger.info("Creating topic: " + controllerConfig.getStreamConfig().getStreamThreatTopicInferState()); 
        return TopicBuilder.name(controllerConfig.getStreamConfig().getStreamThreatTopicInferState()) 
            .partitions(1) 
            .replicas(1)
            .build(); 
    } 

    @Bean
    public NewTopic controlPlaneAnalysisTopic() {
        logger.info("Creating topic: " + controllerConfig.getStreamConfig().getStreamThreatTopic()); 
        return TopicBuilder.name(controllerConfig.getStreamConfig().getStreamThreatTopic())
            .partitions(1)
            .replicas(1)
            .build();
    }
}
