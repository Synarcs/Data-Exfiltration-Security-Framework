#!/bin/sh 

set -e 

# install pdns
sudo dnf install -y pdns pdns-backend-postgresql -y

# start postgresql
docker run pdns -p 5432:5432  -e POSTGRES_PASSWORD=postgres -d postgres


sudo apt-get install -y pdns-server pdns-backend-pgsql
