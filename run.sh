#!/bin/sh 

bazel run //:gazelle -- update-repos -from_file=go.mod
bazel run //:gazelle 


bazel build --repo_env=CC=clang  //... && bazel run //node_agent
