package kprobe

import (
	"reflect"
	"strings"

	"github.com/cilium/ebpf"
)

func GenerateeBPFCollectionspec(progName string, maps []string) (interface{}, error) {
	fields := make([]reflect.StructField, 0)

	// Add Program field to be loaded in kernel
	fields = append(fields, reflect.StructField{
		Name: strings.ToUpper(progName),
		Type: reflect.TypeOf((*ebpf.Program)(nil)),
		Tag:  reflect.StructTag(`ebpf:"` + strings.ToLower(progName) + `"`),
	})

	// Add eBPF maps fields to be loaded in kernel
	for mapId := range maps {
		fields = append(fields, reflect.StructField{
			Name: strings.ToUpper(maps[mapId]),
			Type: reflect.TypeOf((*ebpf.Map)(nil)),
			Tag:  reflect.StructTag(`ebpf:"` + strings.ToLower(maps[mapId]) + `"`),
		})
	}

	eBPFCollectionSpecProbe := reflect.StructOf(fields)
	return reflect.New(eBPFCollectionSpecProbe).Interface(), nil
}
