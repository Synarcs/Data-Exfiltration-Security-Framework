#!/bin/bash

while true; do time python3 -c "import requests as rq; print(rq.get('https://kv801.prod.do.dsp.mp.microsoft.com/').status_code)"; sleep 0.2; done;



