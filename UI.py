import json
import os

import gradio as gr
from alpaca_turbo import Assistant
from prompts import History, Personas
from rich import print as eprint


def trunc(data):
    return data[: min(10, len(data))] if data else "<>"


def quick_summary(data):
    for resp in data:
        return (trunc(resp[1]), None)


class ChatBotUI:
    def __init__(self, assistant) -> None:
        #################
        self._personas = Personas("./prompts.json")
        self._conv = History("./chat_hist.json")
        self._conv.clean()
        self._conv.append([])
        self.assistant: Assistant = assistant
        self.settings = {
            "bot_persona": self.assistant.persona,
            "bot_prompt": self.assistant.prompt,
            "bot_format": self.assistant.format,
        }
        #################

        self.remember_history = gr.Checkbox(
            label="Remember history",
            value=True,
            interactive=True,
        ).style(container=False)
        self.persona = gr.Dropdown(
            self._personas.get_all(),
            label="Personalities",
            value=self._personas.get_all()[0],
            interactive=True,
        )
        self.history_sidebar = gr.Chatbot(self.load_history(), label="History")
        self.chatbot_window = gr.Chatbot([], elem_id="chatbot").style(height=690)
        self.stop_generation = gr.Button("Stop Generating")
        self.input = gr.Textbox(
            show_label=False,
            placeholder="Enter text and press enter shift+enter for new line",
        )
        self.input.style(container=False)

        self.bot_persona = gr.Textbox(
            label="Persona",
            value=lambda: self.settings["bot_persona"],
            interactive=True,
            lines=4,
            visible=False,
        )
        self.bot_prompt = gr.Textbox(
            label="Init Prompt",
            value=lambda: self.settings["bot_prompt"],
            interactive=True,
            lines=4,
            visible=False,
        )
        self.bot_format = gr.TextArea(
            label="Format",
            value=lambda: self.settings["bot_format"],
            interactive=True,
            visible=False,
        )

    def load_history(self):
        """load"""
        entries = []
        if self._conv.data:
            self._conv.clean()
            for chats in self._conv[:-1]:
                # print(chats)
                first_interaction = chats[0]
                bots_resp = str(first_interaction[1])
                if len(bots_resp.split(" ")) > 6:
                    bots_resp = " ".join(bots_resp.split(" ")[:6])
                entries.append((bots_resp, None))
        return entries[::-1]

    def add_text(self, history, text):
        self._conv[-1] = history + [(text, None)] if len(self._conv) > 0 else []
        return self._conv[-1], ""

    def bot(
        self,
        history,
        remember,
        persona,
        prompt,
        format,
    ):
        """Run the bot with entire history"""
        # print(ASSISTANT.enable_history)
        # print(history)
        self.assistant.chat_history = history[:-1] if len(history) >= 1 else []
        user_input = history[-1][0]
        response = ""

        self.assistant.persona = persona
        self.assistant.prompt = prompt
        self.assistant.format = format
        self.assistant.enable_history = remember

        resp = self.assistant.ask_bot(user_input)

        for out in resp:
            response += out
            history[-1] = (user_input, response)
            # print("====")
            # print(history)
            # print("====")
            # print(conv_history)
            # print("====")
            # hist = self.load_history()
            yield history
        self._conv[-1] = history
        # settings.reload()

    def on_select(self, evt: gr.SelectData):  # SelectData is a subclass of EventData
        if self._conv:
            self._conv.append(self._conv[evt.index[0]])
        else:
            self._conv[-1] = self._conv[evt.index[0]]

        return self._conv[evt.index[0]], self.load_history()

    def link_units(self):
        self.chat_submition = self.input.submit(
            self.add_text,
            [self.chatbot_window, self.input],
            [self.chatbot_window, self.input],
        ).then(
            self.bot,
            [
                self.chatbot_window,
                self.remember_history,
                self.bot_persona,
                self.bot_prompt,
                self.bot_format,
            ],
            self.chatbot_window,
        )
        self.stop_generation.click(self.assistant.reload, cancels=self.chat_submition)

        self.persona.change(
            lambda x: self._personas.get(x),
            [self.persona],
            [self.bot_persona, self.bot_prompt, self.bot_format],
        )

        # persona.change(
        #     lambda x: PERSONAS.get(x) + [x],
        #     [persona],
        #     [bot_persona, bot_prompt, bot_format, persona_chat],
        # )

        self.history_sidebar.select(
            self.on_select, None, outputs=[self.chatbot_window, self.history_sidebar]
        )

        self.bot_persona.change(
            self.settings_update,
            inputs=[self.bot_persona, self.bot_prompt, self.bot_format],
        )
        self.bot_prompt.change(
            self.settings_update,
            inputs=[self.bot_persona, self.bot_prompt, self.bot_format],
        )
        self.bot_format.change(
            self.settings_update,
            inputs=[self.bot_persona, self.bot_prompt, self.bot_format],
        )

    def settings_update(self, *params):
        self.settings = {
            "bot_persona": self.bot_persona,
            "bot_prompt": self.bot_prompt,
            "bot_format": self.bot_format,
        }

    def render(self):
        with gr.Row():
            with gr.Column():
                self.remember_history.render()
                self.persona.render()
                self.history_sidebar.render()
            with gr.Column(scale=4):
                with gr.Column():
                    self.chatbot_window.render()
                    self.stop_generation.render()
                    self.input.render()
                    self.bot_format.render()
                    self.bot_prompt.render()
                    self.bot_persona.render()
        self.link_units()


class SettingsUI:
    def __init__(self, asistant: Assistant):
        self.assistant = asistant
        self.assistant.settings.load_settings()

        self.seed = gr.Textbox(
            label="seed", interactive=True, value=lambda: self.assistant.seed
        )
        self.topk = gr.Textbox(
            label="top_k", value=lambda: self.assistant.top_k, interactive=True
        )
        self.topp = gr.Textbox(
            label="top_p", value=lambda: self.assistant.top_p, interactive=True
        )
        self.temperature = gr.Textbox(
            label="temperature", value=lambda: self.assistant.temp, interactive=True
        )
        self.threads = gr.Textbox(
            label="threads", value=lambda: self.assistant.threads, interactive=True
        )
        self.repeate_pen = gr.Textbox(
            label="repeat_penalty",
            value=lambda: self.assistant.repeat_penalty,
            interactive=True,
        )
        self.repeate_lastn = gr.Textbox(
            label="repeat_last_n",
            value=lambda: self.assistant.repeat_last_n,
            interactive=True,
        )
        self.model_path = gr.Textbox(
            label="Path to model",
            value=lambda: self.assistant.model_path,
            interactive=True,
        )

        self.save_button = gr.Button("Apply")

    def apply_settings(self, *params):
        (
            self.assistant.seed,
            self.assistant.top_k,
            self.assistant.top_p,
            self.assistant.temp,
            self.assistant.threads,
            self.assistant.repeat_penalty,
            self.assistant.repeat_last_n,
            self.assistant.model_path,
        ) = params
        self.assistant.settings.save_settings()
        self.assistant.reload()

    def link_units(self):
        self.save_button.click(
            self.apply_settings,
            [
                self.seed,
                self.topk,
                self.topp,
                self.temperature,
                self.threads,
                self.repeate_pen,
                self.repeate_lastn,
                self.model_path,
            ],
        )

    def render(self):
        with gr.Column():
            self.seed.render()
            self.topk.render()
            self.topp.render()
            self.temperature.render()
            self.threads.render()
            self.repeate_pen.render()
            self.repeate_lastn.render()
            self.model_path.render()
            with gr.Row():
                self.save_button.render()

        self.link_units()
