"""
Main launcher
"""

import gradio as gr
from alpaca_turbo import Assistant
from UI import ChatBotUI, PromptPlayUI, SettingsUI

ASSISTANT = Assistant(auto_load=False)
settings = ASSISTANT.settings

gptui = ChatBotUI(ASSISTANT)
settingsui = SettingsUI(ASSISTANT)
promptui = PromptPlayUI(ASSISTANT)

with gr.Blocks(analytics_enabled=False) as demo:
    with gr.Tab("Chat"):
        gptui.render()
    with gr.Tab("Prompt Play ground"):
        promptui.render()
    with gr.Tab("Settings"):
        settingsui.render()

try:
    demo.queue(concurrency_count=2, max_size=20)
    demo.launch(server_port=3000)
    ASSISTANT.program.killx()
except Exception as error:
    ASSISTANT.program.killx()
    raise error
