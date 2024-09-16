gazelle-update-repos:
	bazel run //:gazelle -- update-repos -from_file=go.mod
    bazel run //:gazelle 


gazelle-build:
	bazel build --repo_env=CC=clang  //... && bazel run //node_agent

gazelle:
	bazel run //:gazelle 

node_agent:
	bazel build //node_agent && bazel run //node_agent

kernel:
	bazel run //:kernel 
