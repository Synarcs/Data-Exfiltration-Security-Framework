package com.synarcs.com.protocols;

public interface IFeatureTransportProtocol {
    public String GetProtocolName();
    public Integer GetProtocolDefaultPort();
    public Integer GetProtocolCustomExfiltratedPort();
}