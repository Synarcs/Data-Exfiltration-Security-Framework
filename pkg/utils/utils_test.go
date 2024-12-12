package utils

import (
	"strconv"
	"testing"
)

type TestInput uint32

type TestOutput interface {
	string | []byte
}

type TestProcessInput[T TestOutput] struct {
	Name   string
	Input  uint32
	Output T
}

func getTestInput[T TestOutput]() []TestProcessInput[T] {
	var test []TestProcessInput[T] = []TestProcessInput[T]{
		{
			"parseipv4", 0x0AC80001, T("10.200.0.1"),
		},
		{
			"TeztGetIpv4AddressUserSpaceDpIString", 1, T("10.200.0.1"),
		},
		{
			"TestGetIpv4AddressUserspaceDPI", 1, T([]byte("10.200.0.2")),
		},
	}
	return test
}

func TestParseIpv4(t *testing.T) {
	test := getTestInput[string]()

	for _, test := range test {
		switch test.Name {
		case "parseipv4":
			t.Run(test.Name, func(t *testing.T) {
				t.Parallel()
				if ip := ParseIp(test.Input); ip != test.Output {
					t.Errorf("Error the requred test broke for parsing the ipv4 packet")
				}
				t.Log("Parsed Ipv4 address ", ParseIp(test.Input))
			})
		case "TeztGetIpv4AddressUserSpaceDpIString":
			t.Parallel()
			t.Run(test.Name, func(t *testing.T) {
				if ipv4Parse := GetIpv4AddressUserSpaceDpIString(2); ipv4Parse != BRIDGE_IPAM_IPV4_IP+strconv.Itoa(2) {
					t.Error("error Parsing the Ipv4 Bridge IPAM header")
				}
			})
		case "TestGetIpv4AddressUserspaceDPI":
			t.Run(t.Name(), func(t *testing.T) {
				if parseIp := GetIpv4AddressUserspaceDPI(1); parseIp.String() == test.Output {
					t.Errorf("Error Parsing the Ipv4 Bridge IPAM header")
				}
			})
		case "TestCPUArch":
			t.Run(t.Name(), func(t *testing.T) {
				cores, _ := strconv.Atoi(test.Output)
				if cpu := GetCPUCores(); cpu != cores {
					t.Errorf("Error Parsing the Ipv4 Bridge IPAM header")
				}
			})
		}
	}

}
