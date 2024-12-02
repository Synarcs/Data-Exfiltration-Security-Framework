package com.synarcs.com;


public interface IController {
    void ConfigureKafkaBroker(String brokerUrl, int BrokerPort);
    void ProcessStreamAnalyticsDSl();
}
