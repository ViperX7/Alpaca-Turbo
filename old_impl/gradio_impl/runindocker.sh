#!/bin/bash
cp /alpaca.cpp/main /app/bin/linux
python webui.py -d --load-default
