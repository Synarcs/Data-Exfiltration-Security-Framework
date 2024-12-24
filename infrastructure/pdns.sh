#!/bin/bash 

sudo apt-get -y update 

sudo apt-get install -y pdns-server pdns-backend-pgsql pdns-recursor postgresql

sudo -u postgres createuser pdns

sudo -u postgres createdb pdns

sudo -u postgres psql -c "ALTER USER pdns WITH PASSWORD 'pdns_exfil'"

psql -d pdns -c "GRANT ALL ON ALL TABLES IN SCHEMA public TO pdns;"
psql -d pdns -c "GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO pdns;"


echo "[x] Veridy the pdns process permission"
psql -d pdns -c "\dp"

