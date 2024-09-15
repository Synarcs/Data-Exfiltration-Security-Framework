#!/bin/sh 
set -e 
args=$1

if [[ $args -eq 1 ]]; then
    bazel run //:gazelle -- update-repos -from_file=go.mod
    bazel run //:gazelle 
elif [[ $args -eq 2 ]]; then
    bazel build --repo_env=CC=clang  //... && bazel run //node_agent
else 
    bazel run //node_agent
fi



