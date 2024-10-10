proto_path = proto
go_out = pb 

.PHONY: protoc-gen
protoc-gen:
	protoc --proto_path=$(proto_path) \
	--go_out=$(go_out) \
	--go_opt=paths=source_relative \
	--go-grpc_out=$(go_out) \
	--go-grpc_opt=paths=source_relative,require_unimplemented_servers=false \
	exfil_sec.proto
