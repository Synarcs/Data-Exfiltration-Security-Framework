

node_agent := main.go 
output := main 
debug := false 

.PHONY: build
build:
	go build $(node_agent) 

.PHONY: run 
run: 
	sudo ./main 

.PHONY: build-run 
build-run:
	@echo "running the node_agent"
	go build $(node_agent) 
	sudo ./main 

.PHONY: disas 
disas:
	if [ "$(debug)" = "true" ]; then objdump -d "main"; fi
	gdb main 
