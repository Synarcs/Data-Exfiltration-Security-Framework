.PHONY: build 
build:
	bash build.sh 

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
