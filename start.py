#!/bin/python3
"""
     ▄▄▄· ▄▄▌   ▄▄▄· ▄▄▄·  ▄▄·  ▄▄▄·     ▄▄▄▄▄▄• ▄▌▄▄▄  ▄▄▄▄·
    ▐█ ▀█ ██•  ▐█ ▄█▐█ ▀█ ▐█ ▌▪▐█ ▀█     •██  █▪██▌▀▄ █·▐█ ▀█▪▪
    ▄█▀▀█ ██▪   ██▀·▄█▀▀█ ██ ▄▄▄█▀▀█      ▐█.▪█▌▐█▌▐▀▀▄ ▐█▀▀█▄ ▄█▀▄
    ▐█ ▪▐▌▐█▌▐▌▐█▪·•▐█ ▪▐▌▐███▌▐█ ▪▐▌     ▐█▌·▐█▄█▌▐█•█▌██▄▪▐█▐█▌.▐▌
     ▀  ▀ .▀▀▀ .▀    ▀  ▀ ·▀▀▀  ▀  ▀      ▀▀▀  ▀▀▀ .▀  ▀·▀▀▀▀  ▀█▄▀▪

https;//github.comViperX7/Alpaca-Turbo
"""
import django
import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "turbo_server.settings")
django.setup()

from ai_model_manager.models import AIModelFormat

AIModelFormat.objects.create(name="ggml", extension=".bin").save()
