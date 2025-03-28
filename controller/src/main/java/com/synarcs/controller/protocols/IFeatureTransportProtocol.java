package com.synarcs.controller.protocols;

public interface IFeatureTransportProtocol {
    public String GetExfilProtocolBaseType();
    public Integer GetProtocolDefaultPort();
    public Integer GetProtocolCustomExfiltratedPort();
    public Object GetDnsFeatures();
}