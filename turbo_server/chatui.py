from os import name
from time import time

import flet as ft
from alpaca_turbo import AIModel, Assistant, Conversation, Message
from flet import *
from flet import (ClipBehavior, Column, Container, CrossAxisAlignment, Image,
                  ListTile, MainAxisAlignment, Markdown, OutlinedButton, Page,
                  Row, Text, alignment, border, colors)
from rich import print as eprint
from utils.ui_elements import get_random_color

app_color_scheme = {
    "chat_bot_resp_bg": "#111",
    "chat_user_resp_bg": "#111",
    "chat_page_bg": "#111",
    "chat_input_field_bg": "#293c3a",
    "chat_input_field_font": "#ffffff",
    "chat_input_field_placeholder": "#40414e",
}


def choose_model(index=None):
    """select model from available models or return None

    Returns:
        [TODO:return]
    """
    models = AIModel.objects.all()
    if len(models) == 0:
        return None
    print("Available models:")
    for idx, model in enumerate(models):
        print(f"{idx+1}. {model.name}")

    index = int(input("Choose model: ")) - 1 if index is None else index
    if index < 0 or index >= len(models):
        return None

    return models[index] if index in range(0, len(models)) else None


class ChatUI:
    def __init__(self, page) -> None:
        self.chat_title = None
        self.chat_content = []
        self.page: ft.Page = page
        ### delete chat_content date title

        self.assistant = Assistant(AIModel.objects.first())

        self.lview = ft.ListView(
            expand=1,
            spacing=0,
            # padding=20,
            auto_scroll=True,
            animate_size=20,
        )

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
                Container(
                    Text("hi"),
                    alignment=ft.alignment.center,
                    height=160,
                    bgcolor="blue",
                ),
            ],
        )

        model_options = [
            ft.dropdown.Option(model.id, model.name) for model in AIModel.objects.all()
        ]

        def loading_progress(state):
            return Row(
                alignment=MainAxisAlignment.CENTER,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[ft.ProgressRing(), Text("Loading model please wait ... ")]
                if state == "loading"
                else [Icon(ft.icons.CHECK, color="green"), Text("Model loaded")],
            )

        self.model_selection_screen = Container(
            bgcolor="#112233",
            expand=True,
            content=Column(
                alignment=MainAxisAlignment.CENTER,
                horizontal_alignment=CrossAxisAlignment.CENTER,
                controls=[
                    Container(
                        alignment=ft.alignment.center,
                        # bgcolor="blue",
                        content=Row(
                            alignment=ft.MainAxisAlignment.CENTER,
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            controls=[
                                ft.Dropdown(
                                    width=500,
                                    # label="Model",
                                    # hint_text="Select model",
                                    options=model_options,
                                    value=model_options[0].key,
                                    on_change=lambda x: [
                                        self.model_selection_screen.content.controls.pop()
                                        if len(
                                            self.model_selection_screen.content.controls
                                        )
                                        > 1
                                        else None,
                                        setattr(
                                            self.assistant,
                                            "model",
                                            AIModel.objects.filter(
                                                id=x.control.value
                                            ).first(),
                                        ),
                                        self.model_selection_screen.content.controls.append(
                                            loading_progress("loading")
                                        ),
                                        self.page.update(),
                                        self.assistant.load_model(),
                                        self.model_selection_screen.content.controls.pop(),
                                        self.model_selection_screen.content.controls.append(
                                            loading_progress("loaded")
                                        ),
                                        self.page.update(),
                                    ],
                                ),
                                IconButton(
                                    icon=ft.icons.SETTINGS,
                                ),
                            ],
                        ),
                    ),
                ],
            ),
        )

        self.ui_main_content = Container(
            content=self.model_selection_screen,
            bgcolor="#112233",
            expand=True,
            # height=self.page.window_height-160,
            # width=self.page.window_width*0.8,
        )

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
                        on_click=lambda _: self.assistant.stop_generation(),
                        visible=False,
                    ),
                    TextField(
                        width=800,
                        multiline=True,
                        bgcolor=app_color_scheme["chat_input_field_bg"],
                        border_color=ft.colors.TRANSPARENT,
                        color=app_color_scheme["chat_input_field_font"],
                        border=ft.border.all(0),
                        shift_enter=True,
                        hint_text="Enter To Send and shift enter for new line",
                        on_submit=self.chat_submit,
                    ),
                ],
            ),
        )

        self.full_ui = Container(
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
                                self.ui_main_content,
                                self.ui_input_area,
                            ],
                        ),
                    ),
                ],
            )
        )

    def new_chat(self, _):
        self.page.floating_action_button.disabled = True
        self.page.update()

        # self.assistant = Assistant(self.model_selection_screen.content.controls[0].content.controls[0].content.value)
        # self.assistant.model = (
        #     self.model_selection_screen.content.controls[0].content.controls[0].value
        # )

        self.assistant.unload_model()
        self.assistant.clear_chat()
        self.assistant.new_chat()

        self.ui_main_content.content = self.model_selection_screen
        screen = self.model_selection_screen.content.controls
        _ = screen.pop() if len(screen) > 1  else None
        self.page.update()

        self.chat_content = []
        self.lview.controls = []
        self.ui_sidebar.controls[0].content = Conversation.ui_conversation_list(
            hide_last=True, select_chat_callback=self.load_chat_from_conversation
        )

        self.page.floating_action_button.disabled = False

        self.page.update()

    def toggle_lock(self):
        stop_button, input_text_box = self.ui_input_area.content.controls

        stop_button.visible = not stop_button.visible
        input_text_box.disabled = not input_text_box.disabled
        self.page.update()

    def chat_submit(self, _):
        """Update the interaction"""
        if not self.assistant.is_loaded:
            screen = self.model_selection_screen.content.controls
            screen.append(
                Row(
                    alignment=MainAxisAlignment.CENTER,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    controls=[
                        ft.ProgressRing(),
                        Text("Loading model please wait ... "),
                    ],
                )
            )
            self.model_selection_screen.update()
            print("***")
            print(screen[0].content.controls[0].value)
            print(type(screen[0].content.controls[0].value))
            print("***")

            self.assistant.model = AIModel.objects.filter(
                id=screen[0].content.controls[0].value
            ).first()
            self.assistant.load_model()
            screen.pop()

        self.ui_main_content.content = self.md_chat_generator(self.chat_content)
        stop_button, input_text_box = self.ui_input_area.content.controls

        user_inp = input_text_box.value
        if user_inp:
            self.assistant.conversation.save()
            msg = self.assistant.conversation.add_message(
                user_inp,
                "Thinking...",
                self.assistant.model.prompt.preprompt,
                self.assistant.model.prompt.format,
            )
            msg = self.assistant.sane_check_msg(msg)
            self.chat_content.append(msg)

            input_text_box.value = ""  # empty the input boc
            self.toggle_lock()

            user_msg, ai_msg = msg.get_ui()
            _ = [self.lview.controls.append(ui_ele) for ui_ele in [user_msg, ai_msg]]

            self.lview.update()

            buffer = ""

            generator = self.assistant.chatbot(msg)

            tstart = time()
            msg.ai_response = ""
            for char in generator:
                buffer += char.replace("\n", "  \n")
                sec = str(time() - tstart).split(".")[0]
                word_count = len(buffer.split(" "))

                msg.ai_response = buffer
                msg.save()

                _, ai_msg = msg.get_ui()
                ai_avatar, ai_text, ai_info = ai_msg.content.controls
                ai_info.content.controls[1].value = f"{word_count} w / {sec}s"

                self.lview.controls[-1] = ai_msg


                self.page.update()

            # conv.response = buffer
            # self.chat_content.append(conv)

            self.toggle_lock()

    def conversation2chat(self, uuid):
        self.chat_content = []
        conv = self.assistant.load_chat(uuid)
        print(conv)
        print("-----")
        eprint(conv)
        print("-----")

    def md_chat_generator(self, data):
        final_column = self.lview
        final_column.controls = []

        for entry in data:
            user_in, ai_out = entry.get_ui()
            final_column.controls.append(user_in)
            final_column.controls.append(ai_out)

        return final_column

    def load_chat_from_conversation(self, entry: Conversation):
        entry_id = str(entry.id)
        data: list[Message] = self.assistant.load_chat(entry_id)
        res = []

        for msg in data:
            res.append(msg)

        self.chat_content = res
        self.lview.controls = []
        self.ui_main_content.content = self.md_chat_generator(self.chat_content)
        self.ui_sidebar.controls[0].content = Conversation.ui_conversation_list(
            hide_last=False, select_chat_callback=self.load_chat_from_conversation
        )
        self.page.update()
        return res


def main(page: Page):
    page.horizontal_alignment = "center"
    page.vertical_alignment = "center"
    page.theme_mode = ft.ThemeMode.DARK
    # page.window_height = 1000
    # page.window_width = 1400
    page.bgcolor = "black"
    page.padding = 0
    print("---")
    print(page.window_height)
    print(page.window_width)
    print("---")

    chatui = ChatUI(page)

    page.floating_action_button = FloatingActionButton(
        icon=ft.icons.CHAT, on_click=chatui.new_chat
    )

    # set-up-some-bg-and -main-container
    # The-general-UI‘will-copy- that-of a-mobile-app
    page.add(
        # -this is just-a-bg-container
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
