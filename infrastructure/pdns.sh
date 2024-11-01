#!/bin/sh 

set -e 

# install pdns
sudo dnf install pdns pdns-backend-postgresql -y

# start postgresql
docker run pdns -p 5432:5432  -e POSTGRES_PASSWORD=postgres -d postgres

