import json
import os

import gradio as gr
from alpaca_turbo import Assistant
from UI import ChatBotUI

ASSISTANT = Assistant(auto_load=False)
settings = ASSISTANT.settings

header = """
Placeholder
"""

from prompts import History, Personas

PERSONAS = Personas("./prompts.json")

conv_history = History("./hist.json")
conv_history.clean()

conv_holder: list[gr.Button] = []


def add_text(history, text):
    global conv_history
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
    global conv_history
    for out in resp:
        response += out
        history[-1] = (user_input, response)
        # print("====")
        # print(history)
        # print("====")
        # print(conv_history)
        # print("====")
        yield history, [(trunc(hist[0][1]), None) for hist in conv_history if hist]
    conv_history[-1] = history
    # settings.reload()


def on_select(evt: gr.SelectData):  # SelectData is a subclass of EventData
    return conv_history[evt.index[0]]


def trunc(data):
    return data[: min(10, len(data))] if data else "<>"


def get_history():
    return [(trunc(hist[0][1]), None) for hist in conv_history]




gptui = ChatBotUI(ASSISTANT)

with gr.Blocks(analytics_enabled=False) as demo:
    with gr.Tab("Chat"):
        with gr.Row():
            with gr.Column():
                gptui.remember_history.render()
                gptui.persona.render()
                gptui.history_sidebar.render()
            with gr.Column(scale=4):
                with gr.Column():
                    gptui.chatbot_window.render()
                    gptui.stop_generation.render()
                    gptui.input.render()
                    gptui.bot_format.render()
                    gptui.bot_prompt.render()
                    gptui.bot_persona.render()
    gptui.link_units()

#     with gr.Tab("Tinker Prompt"):
#         with gr.Row():
#             with gr.Column():
#                 with gr.Row():
#                     with gr.Column():
#                         remember_history = gr.Checkbox(
#                             label="Remember history",
#                             value=lambda: settings.get(0),
#                             interactive=True,
#                         )
#                         # history_length = gr.Textbox(
#                         #     label="Max chat history to remember",
#                         #     interactive=True,
#                         #     value=lambda: settings.get(1),
#                         # )
#
#                     persona = gr.Dropdown(
#                         PERSONAS.get_all(),
#                         label="Personalities",
#                         value=lambda: PERSONAS.get_all()[0],
#                         interactive=True,
#                     )
#
#                 bot_persona = gr.Textbox(
#                     label="Persona",
#                     value=lambda: settings.get(9),
#                     interactive=True,
#                     lines=4,
#                 )
#                 bot_prompt = gr.Textbox(
#                     label="Init Prompt",
#                     value=lambda: settings.get(10),
#                     interactive=True,
#                     lines=4,
#                 )
#                 bot_format = gr.TextArea(
#                     label="Format", value=lambda: settings.get(11), interactive=True
#                 )
#                 with gr.Row():
#                     clear_history = gr.Button(value="Clear history")
#                     edit_last = gr.Button(value="Edit last request")
#
#             with gr.Column(scale=4):
#                 chatbot = gr.Chatbot([], elem_id="chatbot").style(height=690)
#
#                 with gr.Column():
#                     stop_generation = gr.Button("Stop Generating")
#
#                     txt = gr.Textbox(
#                         show_label=False,
#                         placeholder="Enter text and press enter shift+enter for new line",
#                     ).style(container=False)
#
#     with gr.Tab("README"):
#         # gr.Markdown(header1)
#         gr.Markdown(header)
#
#     with gr.Tab("settings"):
#         with gr.Column():
#             seed = gr.Textbox(
#                 label="seed", interactive=True, value=lambda: settings.get(1)
#             )
#             topk = gr.Textbox(
#                 label="top_k", value=lambda: settings.get(2), interactive=True
#             )
#             topp = gr.Textbox(
#                 label="top_p", value=lambda: settings.get(3), interactive=True
#             )
#             temperature = gr.Textbox(
#                 label="temperature", value=lambda: settings.get(4), interactive=True
#             )
#             threads = gr.Textbox(
#                 label="threads", value=lambda: settings.get(5), interactive=True
#             )
#             repeate_pen = gr.Textbox(
#                 label="repeat_penalty",
#                 value=lambda: settings.get(6),
#                 interactive=True,
#             )
#             repeate_lastn = gr.Textbox(
#                 label="repeat_last_n",
#                 value=lambda: settings.get(7),
#                 interactive=True,
#             )
#             model_path = gr.Textbox(
#                 label="Path to model",
#                 value=lambda: settings.get(8),
#                 interactive=True,
#             )
#
#             with gr.Row():
#                 save_button = gr.Button("Apply")
#
#     history_sidebar.select(on_select, None, outputs=[chatbot_chat])
#
#     save_button.click(settings.update, get_state())
#     gen = txt.submit(add_text, [chatbot, txt], [chatbot, txt]).then(
#         bot, chatbot, [chatbot, history_sidebar]
#     )
#     stop_generation.click(settings.reload, cancels=gen)
#
#     clear_history.click(lambda: (["hi"]), outputs=[chatbot])
#     remember_history.change(settings.update, get_state())
#     remember_history_chat.change(
#         lambda x: x,
#         remember_history_chat,
#         remember_history,
#     )
#     bot_persona.change(settings.update, get_state())
#     bot_prompt.change(settings.update, get_state())
#     bot_format.change(settings.update, get_state())
#
#     edit_last.click(
#         lambda x: (x[:-1], x[-1][0]), inputs=[chatbot], outputs=[chatbot, txt]
#     )
#
#     persona.change(
#         lambda x: PERSONAS.get(x) + [x],
#         [persona],
#         [bot_persona, bot_prompt, bot_format, persona_chat],
#     )
#
#     ############ CHAT ############
#     gen_chat = txt_chat.submit(
#         add_text, [chatbot_chat, txt_chat], [chatbot_chat, txt_chat]
#     ).then(bot, chatbot_chat, [chatbot_chat, history_sidebar])
#     stop_generation_chat.click(settings.reload, cancels=gen_chat)
#     persona_chat.change(
#         lambda x: PERSONAS.get(x) + [x],
#         [persona_chat],
#         [bot_persona, bot_prompt, bot_format, persona],
#     )
#
# #############################################5
# conv_history.append([])
try:
    demo.queue(concurrency_count=2, max_size=20)
    demo.launch()
    ASSISTANT.program.killx()
except Exception as error:
    ASSISTANT.program.killx()
    raise error
