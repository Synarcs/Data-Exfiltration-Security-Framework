package com.synarcs.controller.config;

public class ControllerKafkaTopics {
    public final static String controllerInferenceTopic = "exfil-sec-infer-controller"; // instruct data plane to blacklist domains in their user space cache over UDP transport
    public final static String controllerInferenceBenignTopic = "exfil-sec-top-benign-sld"; // updates data plane top domain sld cache in userspace
    public final static String controllerInferenceTopicTcp = "exfil-sec-infer-controller-tcp"; // instruct data plane to blacklist domains in their user space cache over TCP transport
}
