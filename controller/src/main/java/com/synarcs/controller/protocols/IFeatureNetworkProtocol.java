package com.synarcs.controller.protocols;

public interface IFeatureNetworkProtocol {
    public String GetProtocolName();
    public Integer GetProtocolCustomExfiltratedL3Ip();
    public Object GetDnsFeatures();
}
