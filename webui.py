import json
import os

import gradio as gr
from alpaca_turbo import Assistant

ASSISTANT = Assistant()
settings = ASSISTANT.settings

header = """
Placeholder
"""

from prompts import Personas

PERSONAS = Personas("./prompts.json")


def add_text(history, text):
    history = history + [(text, None)]
    return history, ""


def yeet_text(history):
    return []


def get_state():
    return [
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
    ]


def bot(history):
    """Run the bot with entire history"""
    # print(ASSISTANT.enable_history)
    # print(history)
    ASSISTANT.chat_history = history[:-1] if len(history) >= 1 else []
    user_input = history[-1][0]
    response = ""
    resp = ASSISTANT.ask_bot(user_input)
    for out in resp:
        response += out
        history[-1] = (user_input, response)
        yield history
    # settings.reload()


with gr.Blocks() as demo:
    with gr.Tab("Chat"):
        with gr.Row():
            with gr.Column():
                with gr.Row():
                    with gr.Column():
                        remember_history = gr.Checkbox(
                            label="Remember history",
                            value=lambda: settings.get(0),
                            interactive=True,
                        )
                        # history_length = gr.Textbox(
                        #     label="Max chat history to remember",
                        #     interactive=True,
                        #     value=lambda: settings.get(1),
                        # )

                    persona = gr.Dropdown(
                        PERSONAS.get_all(),
                        value=lambda: PERSONAS.get_all()[0],
                        interactive=True,
                    )

                bot_persona = gr.Textbox(
                    label="Persona",
                    value=lambda: settings.get(9),
                    interactive=True,
                    lines=4,
                )
                bot_prompt = gr.Textbox(
                    label="Init Prompt",
                    value=lambda: settings.get(10),
                    interactive=True,
                    lines=4,
                )
                bot_format = gr.TextArea(
                    label="Format", value=lambda: settings.get(11), interactive=True
                )
                reload = gr.Button(value="reload model")
                with gr.Row():
                    clear_history = gr.Button(value="Clear history")
                    edit_last = gr.Button(value="Edit last request")

            reload.click(settings.reload)
            persona.change(
                PERSONAS.get,
                [persona],
                [bot_persona, bot_prompt, bot_format],
            )

            with gr.Column():
                chatbot = gr.Chatbot([], elem_id="chatbot").style(height=740)

                with gr.Row():
                    with gr.Column():
                        txt = gr.Textbox(
                            show_label=False,
                            placeholder="Enter text and press enter shift+enter for new line",
                        ).style(container=False)

            txt.submit(add_text, [chatbot, txt], [chatbot, txt]).then(
                bot, chatbot, chatbot
            )

            clear_history.click(lambda: [], outputs=[chatbot])
            edit_last.click(
                lambda x: (x[:-1], x[-1][0]), inputs=[chatbot], outputs=[chatbot, txt]
            )

    with gr.Tab("README"):
        # gr.Markdown(header1)
        gr.Markdown(header)

    with gr.Tab("settings"):
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

    save_button.click(settings.update, get_state())
    remember_history.change(settings.update, get_state())
    bot_persona.change(settings.update, get_state())
    bot_prompt.change(settings.update, get_state())
    bot_format.change(settings.update, get_state())

#############################################5

demo.queue(concurrency_count=1, max_size=20).launch()
demo.launch()
