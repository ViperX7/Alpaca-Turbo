"""

Simple UI abstraction

"""
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
        self.chatwindowstate = []
        self._conv.clean()
        # print(self._conv)
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

        self.llml_path = gr.Dropdown(
            self._personas.get_all(),
            label="Personalities",
            value=self._personas.get_all()[0],
            interactive=True,
        )
        self.persona = gr.Dropdown(
            self._personas.get_all(),
            label="Personalities",
            value=self._personas.get_all()[0],
            interactive=True,
        )
        self.history_sidebar = gr.Chatbot(self.load_history, label="History").style(
            height=660,
        )
        self.chatbot_window = gr.Chatbot([], elem_id="chatbot").style(height=690)

        ## BUTTONS
        self.stop_generation = gr.Button("Stop Generating")
        self.edit_last = gr.Button("Edit last")
        self.new_chat = gr.Button("New chat")
        self.cont_chat = gr.Button("Continue")

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
        self._conv.load()
        # eprint(self._conv.data)

        if self._conv.data:
            for chats in self._conv:
                if chats:
                    first_interaction = chats[0] 
                    bots_resp = str(first_interaction[1])
                    if len(bots_resp.split(" ")) > 6:
                        bots_resp = " ".join(bots_resp.split(" ")[:6])
                    entries.append((bots_resp, None))
        # eprint(entries)
        print(entries)

        return entries

    def add_text(self, history, text):
        # add conversation to chat
        curr_conversation = history + [(text, None)] if history else [(text, None)]
        self.chatwindowstate = curr_conversation
        # if len(self._conv) > 0 else []
        return self.chatwindowstate, ""  # return latest conversation

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

        true_history, current_prompt = history[:-1], history[-1]

        # set the history for the assistant
        self.assistant.chat_history = true_history if len(true_history) > 0 else []
        user_input = current_prompt[0]  # Get the user input
        bot_resp = current_prompt[1] if current_prompt[1] else ""  # Get the user input

        user_input += f"\n{bot_resp}" if bot_resp else ""

        # Settings
        self.assistant.persona = persona
        self.assistant.prompt = prompt
        self.assistant.format = format
        self.assistant.enable_history = remember

        # Query the bot for response
        resp = self.assistant.ask_bot(user_input)

        response = bot_resp
        for out in resp:
            response += out

            # Update the chatbox with live input
            history[-1][1] = response
            self.chatwindowstate = history
            yield history

        # update the conversation
        self.chatwindowstate = history

    def opast_chat_select(
        self, evt: gr.SelectData
    ):  # SelectData is a subclass of EventData
        requested_chat = self._conv[evt.index[0]]

        # check if the chatbot window is occupied
        # if self._conv[-1] != []:  # If occupied
        #     self._conv.data.append([])
        #     self._conv.save()
        #
        # self._conv.load()

        # cleanup
        # cleaned_list = []
        # for converse in self._conv.data:
        #     if converse not in cleaned_list:
        #         cleaned_list.append(converse)
        self._conv.append(self.chatwindowstate)

        self.chatwindowstate = requested_chat

        return requested_chat, self.load_history()

    def get_new_chat(self):
        _ = self._conv.append(self.chatwindowstate) if self.chatwindowstate else None
        self.chatwindowstate = []
        return self.chatwindowstate, self.load_history()

    def modify_last(self):
        conv = self.chatwindowstate
        history = []
        last_conv = []
        if len(conv) > 0:  # check if there are any chats in last conv
            history, last_conv = conv[:-1], conv[-1]

        human_input = last_conv[0] if last_conv else ""
        return history, human_input

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

        self.edit_last.click(
            self.modify_last, outputs=[self.chatbot_window, self.input]
        )
        self.new_chat.click(
            self.get_new_chat, outputs=[self.chatbot_window, self.history_sidebar]
        )

        self.cont_chat.click(
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

        self.persona.change(
            lambda x: self._personas.get(x),
            [self.persona],
            [self.bot_persona, self.bot_prompt, self.bot_format],
        )

        self.history_sidebar.select(
            self.opast_chat_select,
            None,
            outputs=[self.chatbot_window, self.history_sidebar],
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
                self.bot_persona.render()
                self.bot_prompt.render()
                self.bot_format.render()

            with gr.Column(scale=4):
                with gr.Column():
                    self.chatbot_window.render()
                    with gr.Row():
                        self.stop_generation.render()
                        self.new_chat.render()
                        self.edit_last.render()
                        self.cont_chat.render()
                    self.input.render()
        self.link_units()


class PromptPlayUI(ChatBotUI):
    def __init__(self, assistant) -> None:
        super().__init__(assistant)

        self.bot_persona = gr.Textbox(
            label="Persona",
            value=lambda: self.settings["bot_persona"],
            interactive=True,
            lines=4,
        )
        self.bot_prompt = gr.Textbox(
            label="Init Prompt",
            value=lambda: self.settings["bot_prompt"],
            interactive=True,
            lines=4,
        )
        self.bot_format = gr.TextArea(
            label="Format",
            value=lambda: self.settings["bot_format"],
            interactive=True,
        )

        self.history_sidebar = gr.Chatbot(
            self.load_history(), label="History", visible=False
        )



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
        self.n_predict = gr.Textbox(
            label="n_predict", value=lambda: self.assistant.n_predict, interactive=True)

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
            self.assistant.n_predict,
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
                self.n_predict,
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
            self.n_predict.render()
            with gr.Row():
                self.save_button.render()

        self.link_units()






















class ArenaUI:
    def __init__(self, assistant) -> None:
        #################
        self._personas = Personas("./characters.json")
        self._conv = History("./1chat_hist.json")
        self.chatwindowstate = []
        self._conv.clean()
        # print(self._conv)
        self.assistant: Assistant = assistant
        self.settings = {
            "bot_persona": "\n".join(self._personas.get(self._personas.get_all()[0])),
            "bot_persona1": "\n".join(self._personas.get(self._personas.get_all()[0])),
            "bot_prompt": "Below is a conversaion of you talking to someone give appropriate response stick to character",
            "bot_prompt1": "Below is a conversaion of you talking to someone give appropriate response stick to character",
            "bot_format":  "\n### Instruction:\n{instruction}\n\n### Response(you):\n{response}",
            "bot_format1":  "\n### Instruction:\n{instruction}\n\n### Response(you):\n{response}"
        }
        #################


        # self.common_prompt = gr.Textbox("Conversation between a dog and a cat where they discuss how they were domistaced",interactive=True,label="Common Prompt")

        self.remember_history = gr.Checkbox(
            label="Remember history",
            value=True,
            interactive=True,
        ).style(container=False)


        self.remember_history1 = gr.Checkbox(
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


        self.persona1 = gr.Dropdown(
            self._personas.get_all(),
            label="Personalities",
            value=self._personas.get_all()[0],
            interactive=True,
        )


        self.bot_persona = gr.Textbox(
            label="Persona",
            value=lambda: self.settings["bot_persona"],
            interactive=True,
            lines=4,
        )
        self.bot_persona1 = gr.Textbox(
            label="Persona",
            value=lambda: self.settings["bot_persona"],
            interactive=True,
            lines=4,
        )






        self.bot_prompt = gr.Textbox(
            label="Init Prompt",
            value=lambda: self.settings["bot_prompt1"],
            interactive=True,
            lines=4,
        )

        self.bot_prompt1 = gr.Textbox(
            label="Init Prompt",
            value=lambda: self.settings["bot_prompt1"],
            interactive=True,
            lines=4,
        )






        self.bot_format = gr.TextArea(
            label="Format",
            value=lambda: self.settings["bot_format"],### Instruction:\n{instruction}\n\n### Response(you):\n{response}"],
            interactive=True,
        )

        self.bot_format1 = gr.TextArea(
            label="Format",
            value=lambda: self.settings["bot_format"],### Instruction:\n{instruction}\n\n### Response(you):\n{response}"],
            interactive=True,
        )


        self.history_sidebar = gr.Chatbot(self.load_history, label="History").style(
            height=660,visible=False
        )
        self.chatbot_window = gr.Chatbot([], elem_id="chatbot").style(height=660)

        ## BUTTONS
        self.stop_generation = gr.Button("Stop Generating")
        self.edit_last = gr.Button("Edit last")
        self.new_chat = gr.Button("New chat")
        self.cont_chat = gr.Button("Continue")

        self.generate = gr.Button("Generate")
        self.generate1 = gr.Button("Generate")




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
        )
        self.bot_prompt = gr.Textbox(
            label="Init Prompt",
            value=lambda: self.settings["bot_prompt"],
            interactive=True,
            lines=4,
        )
        self.bot_format = gr.TextArea(
            label="Format",
            value=lambda: self.settings["bot_format"],
            interactive=True,
        )

    def load_history(self):
        """load"""
        entries = []
        self._conv.load()
        # eprint(self._conv.data)

        if self._conv.data:
            for chats in self._conv:
                if chats:
                    first_interaction = chats[0] 
                    bots_resp = str(first_interaction[1])
                    if len(bots_resp.split(" ")) > 6:
                        bots_resp = " ".join(bots_resp.split(" ")[:6])
                    entries.append((bots_resp, None))
        # eprint(entries)
        print(entries)

        return entries

    def add_text(self, history, text):
        # add conversation to chat
        curr_conversation = history + [(text, None)] if history else [(text, None)]
        self.chatwindowstate = curr_conversation
        # if len(self._conv) > 0 else []
        return self.chatwindowstate, ""  # return latest conversation



    # def bot1(
    #     self,
    #     history,
    #     remember,
    #     persona,
    #     prompt,
    #     format,
    # ):
    #     """Run the bot with entire history"""
    #     # print(ASSISTANT.enable_history)
    #     # print(history)
    #     print(history)
    #
    #     true_history, current_prompt = history[:-1], history[-1]
    #     print("VVVVV")
    #     print(true_history)
    #     twisted = []
    #     old_human = None
    #     for log in true_history:
    #         human,bot = log
    #         new_log = [bot, old_human]
    #         old_human = human
    #         twisted.append(new_log)
    #     true_history = twisted
    #     print("xxxxx")
    #     print(true_history)
    #
    #     # set the history for the assistant
    #     self.assistant.chat_history = true_history if len(true_history) > 0 else []
    #     user_input = current_prompt[0]  # Get the user input
    #     bot_resp = current_prompt[1] if current_prompt[1] else ""  # Get the user input
    #
    #     user_input += f"\n{bot_resp}" if bot_resp else ""
    #
    #     # Settings
    #     self.assistant.persona = persona
    #     self.assistant.prompt = prompt
    #     self.assistant.format = format
    #     self.assistant.enable_history = remember
    #
    #     # Query the bot for response
    #     resp = self.assistant.ask_bot(user_input)
    #
    #     response = bot_resp
    #     for out in resp:
    #         response += out
    #
    #         # Update the chatbox with live input
    #         history[-1][1] = response
    #         self.chatwindowstate = history
    #         yield history
    #
    #     # update the conversation
    #     self.chatwindowstate = history




    

    def bot1(
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
        print(history)
        ohistory = list(history)

        print("VVVVV")
        print(history)
        twisted = []
        old_human = ""
        for log in history:
            human,bot = log
            new_log = [bot, old_human]
            old_human = human
            twisted.append(new_log)
        history = twisted


        true_history, current_prompt = history[:-1], history[-1]
        print("xxxxx")
        print(true_history)

        # set the history for the assistant
        self.assistant.chat_history = true_history if len(true_history) > 0 else []
        user_input = current_prompt[0]  # Get the user input
        bot_resp = current_prompt[1] if current_prompt[1] else ""  # Get the user input

        user_input += f"\n{bot_resp}" if bot_resp else ""

        # Settings
        self.assistant.persona = persona
        self.assistant.prompt = prompt
        self.assistant.format = format
        self.assistant.enable_history = remember

        # Query the bot for response
        resp = self.assistant.ask_bot(user_input)

        response = bot_resp
        history = ohistory
        history.append( [None,None])
        for out in resp:
            response += out

            # Update the chatbox with live input
            history[len(history)-1][0] = response
            self.chatwindowstate = history
            yield history

        # update the conversation
        print(":::")
        print(history)
        self.chatwindowstate = history




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

        true_history, current_prompt = history[:-1], history[-1]

        # set the history for the assistant
        self.assistant.chat_history = true_history if len(true_history) > 0 else []
        user_input = current_prompt[0]  # Get the user input
        bot_resp = current_prompt[1] if current_prompt[1] else ""  # Get the user input

        user_input += f"\n{bot_resp}" if bot_resp else ""

        # Settings
        self.assistant.persona = persona
        self.assistant.prompt = prompt
        self.assistant.format = format
        self.assistant.enable_history = remember

        # Query the bot for response
        resp = self.assistant.ask_bot(user_input)

        response = bot_resp
        for out in resp:
            response += out

            # Update the chatbox with live input
            history[-1][1] = response
            self.chatwindowstate = history
            yield history

        # update the conversation
        self.chatwindowstate = history

    def opast_chat_select(
        self, evt: gr.SelectData
    ):  # SelectData is a subclass of EventData
        requested_chat = self._conv[evt.index[0]]

        # check if the chatbot window is occupied
        # if self._conv[-1] != []:  # If occupied
        #     self._conv.data.append([])
        #     self._conv.save()
        #
        # self._conv.load()

        # cleanup
        # cleaned_list = []
        # for converse in self._conv.data:
        #     if converse not in cleaned_list:
        #         cleaned_list.append(converse)
        self._conv.append(self.chatwindowstate)

        self.chatwindowstate = requested_chat

        return requested_chat, self.load_history()

    def get_new_chat(self):
        _ = self._conv.append(self.chatwindowstate) if self.chatwindowstate else None
        self.chatwindowstate = []
        return self.chatwindowstate, self.load_history()

    def modify_last(self):
        conv = self.chatwindowstate
        history = []
        last_conv = []
        if len(conv) > 0:  # check if there are any chats in last conv
            history, last_conv = conv[:-1], conv[-1]

        human_input = last_conv[0] if last_conv else ""
        return history, human_input

    def link_units(self):
        self.chat_submition = self.input.submit(
            self.add_text,
            [self.chatbot_window, self.input],
            [self.chatbot_window, self.input],
        )
        # .then(
        #     self.bot,
        #     [
        #         self.chatbot_window,
        #         self.remember_history,
        #         self.bot_persona,
        #         self.bot_prompt,
        #         self.bot_format,
        #     ],
        #     self.chatbot_window,
        # )

        self.generate.click(self.bot,[self.chatbot_window,self.remember_history,self.bot_persona,self.bot_prompt,self.bot_format,],[self.chatbot_window])
        self.generate1.click(self.bot1,[self.chatbot_window,self.remember_history,self.bot_persona1,self.bot_prompt1,self.bot_format1,],[self.chatbot_window])










        self.stop_generation.click(self.assistant.reload, cancels=self.chat_submition)

        self.edit_last.click(
            self.modify_last, outputs=[self.chatbot_window, self.input]
        )
        self.new_chat.click(
            lambda:[], outputs=[self.chatbot_window]
        )

        self.cont_chat.click(
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

        self.persona.change(
            lambda x: "\n".join([x]+self._personas.get(x)),
            [self.persona],
            [self.bot_persona],
        )

        self.persona1.change(
            lambda x: "\n".join([x]+self._personas.get(x)),
            [self.persona1],
            [self.bot_persona1],
        )




        self.history_sidebar.select(
            self.opast_chat_select,
            None,
            outputs=[self.chatbot_window, self.history_sidebar],
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
                # self.history_sidebar.render()
                self.bot_persona.render()
                self.bot_prompt.render()
                self.bot_format.render()
                self.generate.render()

            with gr.Column(scale=4):
                with gr.Column():
                    # self.common_prompt.render()
                    self.chatbot_window.render()
                    with gr.Row():
                        self.stop_generation.render()
                        self.new_chat.render()
                        self.edit_last.render()
                        # self.cont_chat.render()
                    self.input.render()
            with gr.Column():
                self.remember_history1.render()
                self.persona1.render()
                self.bot_persona1.render()
                self.bot_prompt1.render()
                self.bot_format1.render()
                self.generate1.render()




        self.link_units()
