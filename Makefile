.PHONY: build 
build:
	bash build.sh 

.PHONY: build-controller
build-controller:
	@echo "Building the controller"
	cd controller && mvn clean compile install 

.PHONY: run-controller
run-controller:
	@echo "Running the controller"
	cd controller && java -jar target/controller-0.0.1-SNAPSHOT.jar

.PHONY: build-framework 
build-framework:
	@echo "building the framework"
	make build
	make build-controller

.PHONY: gazelle-update-repos
gazelle-update-repos:
	bazel run //:gazelle -- update-repos -from_file=go.mod
    bazel run //:gazelle 

.PHONY: gazelle-build
gazelle-build:
	bazel build --repo_env=CC=clang  //... && bazel run //node_agent

.PHONY: gazelle
gazelle:
	bazel run //:gazelle 

.PHONY: node_agent
node_agent:
	bazel build //node_agent 

.PHONY: kernel
kernel:
	bazel run //:kernel 
