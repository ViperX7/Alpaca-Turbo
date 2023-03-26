#!/bin/python3
"""
Main launcher
"""

import gradio as gr
from alpaca_turbo import Assistant
from UI import ArenaUI, ChatBotUI, PromptPlayUI, SettingsUI

ASSISTANT = Assistant(auto_load=False)
settings = ASSISTANT.settings

gptui = ChatBotUI(ASSISTANT)
settingsui = SettingsUI(ASSISTANT)
promptui = PromptPlayUI(ASSISTANT)
areena = ArenaUI(ASSISTANT)

with gr.Blocks(analytics_enabled=False) as demo:
    with gr.Tab("Areena"):
        areena.render()
    with gr.Tab("Chat"):
        gptui.render()
    with gr.Tab("Prompt Play ground"):
        promptui.render()
    with gr.Tab("Settings"):
        settingsui.render()

try:
    demo.queue(concurrency_count=2, max_size=20)
    demo.launch()
    ASSISTANT.program.killx()
except Exception as error:
    pass
    ASSISTANT.program.killx()
    raise error
