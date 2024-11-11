//
// named.conf
//
// Provided by Red Hat bind package to configure the ISC BIND named(8) DNS
// server as a caching only nameserver (as a localhost DNS resolver only).
//
// See /usr/share/doc/bind*/sample/ for example named configuration files.
//

options {
	listen-on port 53 { 127.0.0.1; 192.168.64.26; };
	listen-on-v6 port 53 { ::1; };
	directory 	"/var/named";
	dump-file 	"/var/named/data/cache_dump.db";
	statistics-file "/var/named/data/named_stats.txt";
	memstatistics-file "/var/named/data/named_mem_stats.txt";
	secroots-file	"/var/named/data/named.secroots";
	recursing-file	"/var/named/data/named.recursing";
	allow-query     { any; };
	/* 
	 - If you are building an AUTHORITATIVE DNS server, do NOT enable recursion.
	 - If you are building a RECURSIVE (caching) DNS server, you need to enable 
	   recursion. 
	 - If your recursive DNS server has a public IP address, you MUST enable access 
	   control to limit queries to your legitimate users. Failing to do so will
	   cause your server to become part of large scale DNS amplification 
	   attacks. Implementing BCP38 within your network would greatly
	   reduce such attack surface 
	*/
	forwarders         { 8.8.8.8; 8.8.4.4; };

	recursion yes;
    dnssec-validation yes;

	managed-keys-directory "/var/named/dynamic";
	geoip-directory "/usr/share/GeoIP";

	pid-file "/run/named/named.pid";
	session-keyfile "/run/named/session.key";

	/* https://fedoraproject.org/wiki/Changes/CryptoPolicy */
	include "/etc/crypto-policies/back-ends/bind.config";
};

logging {
    channel query_logging {
        file "/var/log/named/query.log" versions 3 size 10m;  # Log queries to a file
        severity debug 10;        # Set a higher debug level for more details
        print-time yes;          # Add timestamps to log entries
        print-category yes;      # Show the log category in each log line
        print-severity yes;      # Show severity level
    };

    category queries { query_logging; };   # Log query details
    category resolver { query_logging; };  # Log resolver actions
    category client { query_logging; };    # Log client interactions
    category cname { query_logging; };     # Log CNAME processing details
    category edns-disabled { query_logging; };  # Log EDNS issues, if any
};

zone "." IN {
	type hint;
	file "named.ca";
};

include "/etc/named.rfc1912.zones";
include "/etc/named.root.key";

