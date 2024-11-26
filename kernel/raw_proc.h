#ifndef UDP_PORTS_H
#define UDP_PORTS_H

// stop performing any DPI on the most used protocols for udp for transfer 
struct PortMapping {
    const char* protocol;
    int port;
};

static const struct PortMapping UDP_PROTOCOLS[] = {
    {"DNS", 53},
    {"DHCP Client", 68},
    {"DHCP Server", 67},
    {"TFTP", 69},
    {"NTP", 123},
    {"SNMP", 161},
    {"SNMP Trap", 162},
    {"RIP", 520},
    {"Syslog", 514},
    {"RADIUS", 1812},
    {"L2TP", 1701},
    {"OpenVPN", 1194},
    {"Steam Gaming", 27015},
    {"Minecraft", 25565},
    {"VoIP (SIP)", 5060},
    {"RTP Media", 16384},
    {"NetBIOS Name Service", 137},
    {"NetBIOS Datagram", 138},
    {"Microsoft SQL Monitor", 1434},
    {"QUIC", 443},
    {"ISAKMP/IKE", 500},
    {"Kerberos", 88}
};


#endif

