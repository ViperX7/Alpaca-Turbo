import json
import os

import gradio as gr
from alpaca_turbo_jp import Assistant

ASSISTANT = Assistant()
settings = ASSISTANT.settings

header = """
Placeholder
"""


def add_text(history, text):
    history = history + [(text, None)]
    return history, ""


def bot(history):
    """Run the bot with entire history"""
    # print(ASSISTANT.enable_history)
    # print(history)
    ASSISTANT.chat_history = history[:-1] if len(history) >= 1 else []
    user_input = history[-1][0]
    response = ""
    resp = ASSISTANT.ask_bot(user_input).encode
    for out in resp:
        response += out
        history[-1] = (user_input, response)
        yield history

with gr.Blocks() as demo:
    with gr.Tab("Chat"):
        chatbot = gr.Chatbot([], elem_id="chatbot").style(height=500)

        with gr.Row():
            with gr.Column():
                txt = gr.Textbox(
                    show_label=False,
                    placeholder="Enter text and press enter shift+enter for new line",
                ).style(container=False)
                reload = gr.Button(value="reload model")

        txt.submit(add_text, [chatbot, txt], [chatbot, txt]).then(bot, chatbot, chatbot)
        reload.click(settings.reload)

    with gr.Tab("README"):
        # gr.Markdown(header1)
        gr.Markdown(header)

    with gr.Tab("settings"):
        with gr.Row():
            with gr.Column():
                remember_history = gr.Checkbox(
                    label="Remember history",
                    value=lambda: settings.get(0),
                    interactive=True,
                )
                bot_persona = gr.TextArea(
                    label="Persona", value=lambda: settings.get(9), interactive=True
                )
                bot_prompt = gr.TextArea(
                    label="Init Prompt",
                    value=lambda: settings.get(10),
                    interactive=True,
                )
                bot_format = gr.TextArea(
                    label="Format", value=lambda: settings.get(11), interactive=True
                )

            with gr.Column():
                seed = gr.Textbox(
                    label="seed", interactive=True, value=lambda: settings.get(1)
                )
                topk = gr.Textbox(
                    label="top_k", value=lambda: settings.get(2), interactive=True
                )
                topp = gr.Textbox(
                    label="top_p", value=lambda: settings.get(3), interactive=True
                )
                temperature = gr.Textbox(
                    label="temperature", value=lambda: settings.get(4), interactive=True
                )
                threads = gr.Textbox(
                    label="threads", value=lambda: settings.get(5), interactive=True
                )
                repeate_pen = gr.Textbox(
                    label="repeat_penalty",
                    value=lambda: settings.get(6),
                    interactive=True,
                )
                repeate_lastn = gr.Textbox(
                    label="repeat_last_n",
                    value=lambda: settings.get(7),
                    interactive=True,
                )
                model_path = gr.Textbox(
                    label="Path to model",
                    value=lambda: settings.get(8),
                    interactive=True,
                )

                with gr.Row():
                    save_button = gr.Button("Apply")

    save_button.click(
        settings.update,
        [
            remember_history,
            seed,
            topk,
            topp,
            temperature,
            threads,
            repeate_pen,
            repeate_lastn,
            model_path,
            bot_persona,
            bot_prompt,
            bot_format,
        ],
    )

demo.queue(concurrency_count=1, max_size=20).launch()
demo.launch()

