#!/bin/bash



for i in {1..500}; do seq 100 | xargs -n1 -P100 -I{}  kdig t.bleed.io  A; done