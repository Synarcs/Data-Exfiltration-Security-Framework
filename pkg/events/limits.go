package events

var DNS_LIMITS_CONFIG map[uint32]uint32 = map[uint32]uint32{
	0: 130, // MIN_DOMAIN_LENGTH
	1: 255, // MAX_DOMAIN_LENGTH

	2: 17, // MIN_SUBDOMAIN_LENGTH_PER_LABEL
	3: 63, // MAX_SUBDOMAIN_LENGTH_PER_LABEL

	4: 3,   // MIN_LABEL_COUNT
	5: 128, // MAX_LABEL_COUNT

	6: 3,   // (5 - (tld + root) == 3) // MIN_SUBDOMAIN_LENGTH_EXCLUDING_TLD
	7: 125, // (127 - (tld - root) == 125) // MAX_SUBDOMAIN_LENGTH_EXCLUDING_TLD
}
