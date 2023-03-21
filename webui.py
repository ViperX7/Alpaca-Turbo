import json

import gradio as gr
from alpaca_turbo import Assistant
from rich import print as eprint

ASSISTANT = Assistant()
# ASSISTANT.prep_model()

header = """
## Note
- Any change on settings page on the right side will reload the model will take 5-10 seconds
- Settings on the left side can be modified any time 
- Remembering history is expensive for some reason
"""

header1 = """
## Features
- No blabbering
- No reloading model again and again
- Load once run multiple times
- Bot won't repeating what you said
- can remember history
- Settings are saved across restarts
- Easy to configure and Even easier to use
"""


def update_settings(*settings):
    old_settings = get_settings()
    (
        ASSISTANT.enable_history,
        ASSISTANT.seed,
        ASSISTANT.top_k,
        ASSISTANT.top_p,
        ASSISTANT.temp,
        ASSISTANT.threads,
        ASSISTANT.repeat_penalty,
        ASSISTANT.repeat_last_n,
        ASSISTANT.model_path,
        ASSISTANT.persona,
        ASSISTANT.prompt,
        ASSISTANT.format,
    ) = settings

    ASSISTANT.enable_history = int(ASSISTANT.enable_history)
    ASSISTANT.seed = int(ASSISTANT.seed)
    ASSISTANT.top_k = int(ASSISTANT.top_k)
    ASSISTANT.top_p = float(ASSISTANT.top_p)
    ASSISTANT.temp = float(ASSISTANT.temp)
    ASSISTANT.threads = int(ASSISTANT.threads)
    ASSISTANT.repeat_penalty = float(ASSISTANT.repeat_penalty)
    ASSISTANT.repeat_last_n = int(ASSISTANT.repeat_last_n)

    new_settings = get_settings()

    if old_settings[:-3] != new_settings[:-3] and ASSISTANT.is_ready:
        ASSISTANT.program.kill()
        ASSISTANT.is_ready = False
        ASSISTANT.prep_model()

    with open("settings.dat", "w") as file:
        json.dump(settings, file)


def get_settings(n=None):
    order = [
        ASSISTANT.enable_history,
        ASSISTANT.seed,
        ASSISTANT.top_k,
        ASSISTANT.top_p,
        ASSISTANT.temp,
        ASSISTANT.threads,
        ASSISTANT.repeat_penalty,
        ASSISTANT.repeat_last_n,
        ASSISTANT.model_path,
        ASSISTANT.persona,
        ASSISTANT.prompt,
        ASSISTANT.format,
    ]

    result = order if n is None else order[n]
    return result


def load_settings():
    with open("settings.dat", "r") as file:
        settings = json.load(file)
    update_settings(*settings)




def add_text(history, text):
    history = history + [(text, None)]
    return history, ""


def bot(history):
    """Run the bot with entire history"""
    # print(ASSISTANT.enable_history)
    # print(history)
    ASSISTANT.chat_history = history[:-1] if len(history) >=1 else []
    user_input = history[-1][0]
    response = ""
    response = "".join(list(ASSISTANT.ask_bot(user_input)))
    history[-1] = (user_input, response)
    print(history)
    return history


with gr.Blocks() as demo:
    with gr.Tab("Chat"):
        chatbot = gr.Chatbot([], elem_id="chatbot").style(height=750)

        with gr.Row():
            with gr.Column():
                txt = gr.Textbox(
                    show_label=False,
                    placeholder="Enter text and press enter shift+enter for new line",
                ).style(container=False)

        txt.submit(add_text, [chatbot, txt], [chatbot, txt]).then(bot, chatbot, chatbot)

    with gr.Tab("README"):
        gr.Markdown("# Instructions to use")
        with gr.Row():
            gr.Markdown(header1)
            gr.Markdown(header)

    with gr.Tab("settings"):
        with gr.Row():
            with gr.Column():
                remember_history = gr.Checkbox(
                    label="Remember history",
                    value=lambda: get_settings(0),
                    interactive=True,
                )
                bot_persona = gr.TextArea(
                    label="Persona", value=lambda:get_settings(9), interactive=True
                )
                bot_prompt = gr.TextArea(
                    label="Init Prompt", value=lambda:get_settings(10), interactive=True
                )
                bot_format = gr.TextArea(
                    label="Format", value=lambda: get_settings(10), interactive=True
                )

            with gr.Column():
                seed = gr.Textbox(
                    label="seed", interactive=True, value=lambda: get_settings(1)
                )
                topk = gr.Textbox(
                    label="top_k", value=lambda: get_settings(2), interactive=True
                )
                topp = gr.Textbox(
                    label="top_p", value=lambda: get_settings(3), interactive=True
                )
                temperature = gr.Textbox(
                    label="temperature", value=lambda: get_settings(4), interactive=True
                )
                threads = gr.Textbox(
                    label="threads", value=lambda: get_settings(5), interactive=True
                )
                repeate_pen = gr.Textbox(
                    label="repeat_penalty",
                    value=lambda: get_settings(6),
                    interactive=True,
                )
                repeate_lastn = gr.Textbox(
                    label="repeat_last_n",
                    value=lambda: get_settings(7),
                    interactive=True,
                )
                model_path = gr.Textbox(
                    label="Path to model",
                    value=lambda: get_settings(8),
                    interactive=True,
                )

                with gr.Row():
                    save_button = gr.Button("Apply")

    save_button.click(
        update_settings,
        [
            remember_history,
            seed,
            topk,
            topp,
            temperature,
            threads,
            repeate_pen,
            repeate_lastn,
            bot_persona,
            bot_prompt,
            bot_format,
            model_path,
        ],
    )

demo.launch()
