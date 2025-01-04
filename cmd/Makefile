
.PHONY: build 
build:
	@echo "Compile eBPF Node agent cli utils for arg $(shell go env GOOS) $(shell go env GOARCH)"
	go build main.go 

.PHONY: usage
usage:
	@echo "Printing the Usage for the CLI Library for eBPF Node Agent" 
	sudo ./main --help 
