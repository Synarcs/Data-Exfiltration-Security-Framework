package com.synarcs.controller;


public interface IController {
    void ConfigureKafkaBroker(String brokerUrl, int BrokerPort);
    void ProcessStreamAnalyticsDSl();
}
