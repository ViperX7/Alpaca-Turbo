#!/bin/python3
"""
     ▄▄▄· ▄▄▌   ▄▄▄· ▄▄▄·  ▄▄·  ▄▄▄·     ▄▄▄▄▄▄• ▄▌▄▄▄  ▄▄▄▄·
    ▐█ ▀█ ██•  ▐█ ▄█▐█ ▀█ ▐█ ▌▪▐█ ▀█     •██  █▪██▌▀▄ █·▐█ ▀█▪▪
    ▄█▀▀█ ██▪   ██▀·▄█▀▀█ ██ ▄▄▄█▀▀█      ▐█.▪█▌▐█▌▐▀▀▄ ▐█▀▀█▄ ▄█▀▄
    ▐█ ▪▐▌▐█▌▐▌▐█▪·•▐█ ▪▐▌▐███▌▐█ ▪▐▌     ▐█▌·▐█▄█▌▐█•█▌██▄▪▐█▐█▌.▐▌
     ▀  ▀ .▀▀▀ .▀    ▀  ▀ ·▀▀▀  ▀  ▀      ▀▀▀  ▀▀▀ .▀  ▀·▀▀▀▀  ▀█▄▀▪

https;//github.comViperX7/Alpaca-Turbo
"""
from os import name
from time import time

import flet as ft
from alpaca_turbo import AIModel, Assistant, Conversation, Message
from flet import *
from flet import (ClipBehavior, Column, Container, CrossAxisAlignment, Image,
                  ListTile, MainAxisAlignment, Markdown, OutlinedButton, Page,
                  Row, Text, alignment, border, colors)
from rich import print as eprint
from utils.model_selector import model_selector
from utils.status_widget import status_widget
from utils.ui_elements import SliderWithInput, get_random_color

app_color_scheme = {
    "chat_bot_resp_bg": "#111",
    "chat_user_resp_bg": "#111",
    "chat_page_bg": "#111",
    "chat_input_field_bg": "#293c3a",
    "chat_input_field_font": "#ffffff",
    "chat_input_field_placeholder": "#40414e",
}


class CompletionUI:
    def __init__(self, page) -> None:
        self.name = "Completions"
        self.chat_title = None
        self.page: ft.Page = page

        self.assistant = Assistant(AIModel.objects.first())

        self.full_ui()

        self.page.update()

    def full_ui(self):
        self.ui_sidebar = Column(
            alignment=MainAxisAlignment.SPACE_BETWEEN,
            horizontal_alignment=CrossAxisAlignment.CENTER,
            controls=[
                Container(
                    expand=True,
                    content=Conversation.ui_conversation_list(
                        hide_last=True,
                        select_chat_callback=self.load_chat_from_conversation,
                    ),
                    alignment=ft.alignment.center,
                    # height=self.page.window_height-160,
                ),
                # status_widget(),
            ],
        )

        self.words2gen = SliderWithInput(
            "Max words to generate",
            min=1,
            max=100,
            divisions=99,
            value=20,
        )

        self.completion_field = TextField(
            bgcolor=ft.colors.BLUE_900,
            color=ft.colors.WHITE,
            expand=True,
            multiline=True,
            min_lines=50,
            label="Text completion",
            value="The planet on which we live i",
        )

        self.comp_screen = Container(
            margin=ft.margin.all(40),
            content=Column(
                alignment=MainAxisAlignment.CENTER,
                horizontal_alignment=CrossAxisAlignment.CENTER,
                controls=[
                    self.completion_field,
                    self.words2gen.getui(),
                ],
            ),
        )

        self.model_selection_screen = model_selector(self.assistant)

        self.ui_main_util = Container(
            content=self.model_selection_screen,
            bgcolor="#112233",
            expand=True,
        )

        stop_generation = lambda _: self.assistant.stop_generation()

        self.next_screen = lambda _: [
            setattr(self.ui_main_util, "content", self.comp_screen),
            setattr(
                self.ui_input_area.content.controls[1].controls[0], "visible", False
            ),
            setattr(
                self.ui_input_area.content.controls[1].controls[1], "visible", True
            ),
            self.page.update(),
        ]

        self.ui_input_area = Container(
            alignment=ft.alignment.bottom_center,
            padding=10,
            bgcolor="#293040",
            height=160,
            # expand=20,
            content=Column(
                alignment=MainAxisAlignment.SPACE_AROUND,
                horizontal_alignment=CrossAxisAlignment.CENTER,
                controls=[
                    OutlinedButton(
                        text="Stop Generation",
                        icon=ft.icons.STOP,
                        on_click=stop_generation,
                        visible=False,
                    ),
                    Row(
                        alignment=MainAxisAlignment.CENTER,
                        vertical_alignment=CrossAxisAlignment.CENTER,
                        controls=[
                            ElevatedButton(
                                content=Container(
                                    content=Text("Next"),
                                    padding=20,
                                ),
                                width=250,
                                bgcolor=app_color_scheme["chat_input_field_bg"],
                                color=app_color_scheme["chat_input_field_font"],
                                on_click=self.next_screen,
                            ),
                            ElevatedButton(
                                content=Container(
                                    content=Text("Trigger Completion"),
                                    padding=20,
                                ),
                                width=250,
                                bgcolor=app_color_scheme["chat_input_field_bg"],
                                color=app_color_scheme["chat_input_field_font"],
                                visible=False,
                                on_click=self.trigger_completion,
                            ),
                        ],
                    ),
                ],
            ),
        )

        self.main_content = Container(
            content=Row(
                alignment=MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    Container(
                        expand=20,
                        bgcolor="#1e242e",
                        content=self.ui_sidebar,
                    ),
                    Container(
                        expand=80,
                        bgcolor=get_random_color(),
                        # content=Text("80 main content"),
                        content=Column(
                            expand=True,
                            alignment=MainAxisAlignment.SPACE_BETWEEN,
                            controls=[
                                self.ui_main_util,
                                self.ui_input_area,
                            ],
                        ),
                    ),
                ],
            )
        )

        return self.main_content

    def fab(self):
        return FloatingActionButton(icon=ft.icons.CHAT, on_click=self.new_chat)

    def new_chat(self, _):
        self.page.floating_action_button.disabled = True
        self.page.update()

        self.assistant.unload_model()
        self.assistant.clear_chat()
        self.assistant.new_chat()

        self.completion_field.value = ""

        self.ui_main_util.content = self.model_selection_screen
        screen = self.model_selection_screen.content.controls
        _ = screen.pop() if len(screen) > 1 else None
        self.page.update()

        setattr(self.ui_input_area.content.controls[1].controls[0], "visible", True),
        setattr(self.ui_input_area.content.controls[1].controls[1], "visible", False)

        self.ui_sidebar.controls[0].content = Conversation.ui_conversation_list(
            hide_last=True, select_chat_callback=self.load_chat_from_conversation
        )

        self.page.floating_action_button.disabled = False

        self.page.update()

    def toggle_lock(self):
        stop_button = self.ui_input_area.content.controls[0]

        trigger_button = self.ui_input_area.content.controls[1].controls[1]
        trigger_button.disabled = not trigger_button.disabled

        stop_button.visible = not stop_button.visible
        self.page.update()

    def trigger_completion(self, _):
        """Update the interaction"""

        _ = "" if self.assistant.is_loaded else self.assistant.load_model()

        self.toggle_lock()
        self.ui_main_util.content = self.comp_screen
        self.comp_screen.content.controls[0].label = self.assistant.model.name

        input_text_box, _ = self.comp_screen.content.controls

        user_inp = input_text_box.value
        if user_inp:
            prevmsg = self.assistant.conversation.get_all_text()

            if len(prevmsg) <= len(user_inp) and prevmsg in user_inp[: len(user_inp)]:
                # print("hit")
                user_inp = user_inp.replace(prevmsg, "")

            msg = self.assistant.conversation.add_message(
                user_inp, "", input_text_box.value
            )

            buffer = ""
            count = int(self.words2gen.value)

            generator = self.assistant.completion(msg, count)

            tstart = time()
            msg.ai_response = ""
            for char in generator:
                buffer += char.replace("\n", "  \n")
                sec = str(time() - tstart).split(".")[0]
                word_count = len(buffer.split(" "))

                msg.ai_response = buffer
                msg.save()

                input_text_box.value += char.replace("\n", "  \n")

                self.page.update()

        self.toggle_lock()

    def load_chat_from_conversation(self, entry: Conversation):
        entry_id = str(entry.id)
        data: list[Message] = self.assistant.load_chat(entry_id)
        txt = data[-1] if len(data) > 0 else None
        if txt != None:
            txt2show = str(txt.preprompt if txt.preprompt else "") + str(
                txt.ai_response if txt.ai_response else ""
            )
        else:
            txt2show = ""

        res = []

        for msg in data:
            res.append(msg)

        self.ui_main_util.content = self.comp_screen
        self.comp_screen.content.controls[0].value = txt2show
        self.ui_sidebar.controls[0].content = Conversation.ui_conversation_list(
            hide_last=False, select_chat_callback=self.load_chat_from_conversation
        )
        self.page.update()
        return res


def main(page: Page):
    page.horizontal_alignment = "center"
    page.vertical_alignment = "center"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = "black"
    page.padding = 0

    chatui = CompletionUI(page)

    page.floating_action_button = chatui.fab()

    page.add(
        Container(
            margin=0,
            padding=0,
            expand=True,
            bgcolor="blue",
            alignment=ft.alignment.center,
            content=chatui.full_ui,
        ),
    )

    page.update()


_ = (
    ft.app(
        target=main,
        assets_dir="assets",
        port=5555,
        # view=ft.WEB_BROWSER,
    )
    if __name__ == "__main__"
    else None
)
