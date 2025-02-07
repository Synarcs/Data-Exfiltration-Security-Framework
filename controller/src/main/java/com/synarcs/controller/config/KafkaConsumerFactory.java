package com.synarcs.controller.config;

import java.util.HashMap;
import java.util.Map;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.annotation.EnableKafka;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.support.serializer.JsonDeserializer;

import com.synarcs.controller.config.yaml.Config;
import com.synarcs.controller.streamserdes.DnsFeatures;

@EnableKafka
@Configuration
public class KafkaConsumerFactory {

    private final Config controllerConfig;
    
    @Autowired
    public KafkaConsumerFactory(Config config) {
        this.controllerConfig = config;
    }

    @Bean
    public ConsumerFactory<String, DnsFeatures> consumerFactory() {
        Map<String, Object> props = new HashMap<>();
        // kept this to have controller have isolated config files
        props.put(
        ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, 
            controllerConfig.getStreamConfig().getHost()+":"+controllerConfig.getStreamConfig().getBrokerPort());
        props.put(
        ConsumerConfig.GROUP_ID_CONFIG, 
            controllerConfig.getStreamConfig().getConsumerGroupName());
        props.put(
            ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, 
            StringDeserializer.class);
        props.put(
            ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, 
            JsonDeserializer.class);
        props.put(
            ConsumerConfig.AUTO_OFFSET_RESET_CONFIG,
            "earliest"
        );
        props.put(
            ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, 
            true
        );
        props.put("schema.registry.url", "http://"+controllerConfig.getStreamConfig().getSchemaRegistry().getHost() + ":" + controllerConfig.getStreamConfig().getSchemaRegistry().getPort());
            return new DefaultKafkaConsumerFactory<>(props, new StringDeserializer(), new JsonDeserializer(DnsFeatures.class));
   
    }


    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, DnsFeatures> 
      maliciousDomainsListenerFactory() {
   
        ConcurrentKafkaListenerContainerFactory<String, DnsFeatures> factory = 
                        new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(consumerFactory());
        return factory;
    }
}
