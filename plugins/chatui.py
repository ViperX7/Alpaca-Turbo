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
        self.name = "Chat"
        self.chat_title = None
        self.page: ft.Page = page
        ### delete chat_content date title

        self.assistant = Assistant(AIModel.objects.first())
        self.assistant.conversation.save()
        self.bmsheet = None
        self.full_ui()

    def full_ui(self):
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
                    Row(
                        alignment=MainAxisAlignment.CENTER,
                        vertical_alignment=CrossAxisAlignment.CENTER,
                        controls=[
                            ft.IconButton(
                                content=ft.Image(
                                    src="./assets/GitHub-Mark.png", height=30, width=30
                                ),
                                on_click=lambda _:self.page.launch_url(
                                    "https://github.com/ViperX7/Alpaca-Turbo"
                                ),
                            ),
                            ft.IconButton(
                                content=ft.Image(
                                    src="./assets/discord.png", height=30, width=30
                                ),
                                on_click=lambda _:self.page.launch_url(
                                    "https://github.com/ViperX7/Alpaca-Turbo"
                                ),
                            ),
                        ],
                    ),
                    alignment=ft.alignment.center,
                    height=160,
                    bgcolor="#223322",
                    padding=20,
                )
                # status_widget(),
            ],
        )

        self.model_selection_screen = model_selector(self.assistant)

        self.ui_main_content = Container(
            content=self.model_selection_screen,
            bgcolor="#112233",
            expand=True,
            # height=self.page.window_height-160,
            # width=self.page.window_width*0.8,
        )

        self.input_field = TextField(
            width=800,
            multiline=True,
            bgcolor=app_color_scheme["chat_input_field_bg"],
            border_color=ft.colors.TRANSPARENT,
            color=app_color_scheme["chat_input_field_font"],
            border=ft.border.all(0),
            shift_enter=True,
            hint_text="Enter To Send and shift enter for new line",
            on_submit=lambda _: self.chat_submit(),
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
                    Row(
                        alignment=MainAxisAlignment.CENTER,
                        controls=[
                            Column(
                                controls=[
                                    ft.IconButton(
                                        icon=ft.icons.REFRESH,
                                        on_click=lambda _: [
                                            setattr(self.assistant, "last_in_mem", 0),
                                            setattr(
                                                self.page,
                                                "snack_bar",
                                                ft.SnackBar(
                                                    content=ft.Text(
                                                        "Entire conversation will be recontextualized on next generation"
                                                    )
                                                ),
                                            ),
                                            setattr(self.page.snack_bar, "open", True),
                                            self.page.update(),
                                        ],
                                    ),
                                    ft.IconButton(
                                        icon=ft.icons.SETTINGS,
                                        on_click=lambda _: [
                                            self.toggle_bottom_sheet(),
                                        ],
                                    ),
                                ]
                            ),
                            self.input_field,
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
                                self.ui_main_content,
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

        # self.assistant = Assistant(self.model_selection_screen.content.controls[0].content.controls[0].content.value)
        # self.assistant.model = (
        #     self.model_selection_screen.content.controls[0].content.controls[0].value
        # )

        if self.assistant.is_loaded:
            self.assistant.unload_model()
        self.assistant.clear_chat()
        self.assistant.new_chat()

        self.model_selection_screen = model_selector(self.assistant)
        self.ui_main_content.content = self.model_selection_screen
        self.page.update()

        self.lview.controls = []
        self.ui_sidebar.controls[0].content = Conversation.ui_conversation_list(
            hide_last=True, select_chat_callback=self.load_chat_from_conversation
        )

        self.page.floating_action_button.disabled = False

        self.page.update()

    def toggle_bottom_sheet(self):
        if self.bmsheet:
            self.bmsheet.open = not self.bmsheet.open
        else:
            self.bmsheet = ft.BottomSheet(
                ft.Container(
                    ft.Column(
                        [
                            self.assistant.settings.get_ui(),
                            ft.ElevatedButton("Close bottom sheet"),
                        ],
                        tight=True,
                        scroll=True,
                    ),
                    padding=10,
                ),
                open=True,
            )
            self.page.overlay.append(self.bmsheet)
            self.page.update()

        self.bmsheet.update()
        return self.bmsheet

        bs.open = True
        bs.update()

    def toggle_lock(self):
        stop_button, _ = self.ui_input_area.content.controls
        input_text_box = self.input_field

        stop_button.visible = not stop_button.visible
        input_text_box.disabled = not input_text_box.disabled
        self.page.update()

    def load_with_ui(self):
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
        # print("***")
        # print(screen[0].content.controls[0].value)
        # print(type(screen[0].content.controls[0].value))
        # print("***")

        self.assistant.model = AIModel.objects.filter(
            id=screen[1].content.controls[0].value
        ).first()
        self.assistant.load_model()
        screen.pop()

    def get_ui_idx_from_message(self, main_message: Message):
        all_messages = main_message.conversation.get_messages()
        # eprint(all_messages)
        all_messages = all_messages[: main_message.index]
        # eprint(all_messages)
        # eprint(main_message.index)
        idx = -1
        for i, m in enumerate(all_messages):
            idx += 1 if m.preprompt else 0
            idx += 1 if m.user_request else 0
            idx += 1
        return idx

    def chat_submit(self, msg=None):
        """Update the interaction"""

        self.assistant.conversation.save()


        if msg and not isinstance(msg, Message):
            msg = Message.objects.filter(id=msg).first()

        ori_msg = bool(msg)

        # print("Chat submitted...")
        # print(f"Message provided: {ori_msg}")
        # if ori_msg:
        #     print(f"\t\tConversation: {msg.id}")

        # Load model if not loaded
        if not self.assistant.is_loaded:
            if len(list(self.assistant.conversation)):
                self.assistant.load_model()
            else:
                self.load_with_ui()

        # Sync the UI with currently active conversation in assistant
        self.ui_main_content.content = self.md_chat_generator(
            self.assistant.conversation
        )

        input_text_box = self.input_field

        user_inp = input_text_box.value  # If user sends something

        if msg is None:
        # there is some user input but no message object
            if user_inp :
                # Add new message to the end of the list and reset input field
                msg = self.assistant.conversation.add_message(
                    user_inp,
                    "",
                    self.assistant.model.prompt.preprompt if len(list(self.assistant.conversation)) == 0 else None,
                    self.assistant.model.prompt.format,
                )
                msg = self.assistant.sane_check_msg(
                    msg
                )  # this clears duplicate preprompts
                msg.save()
                input_text_box.value = ""  # empty the input boc
            else:
                print("No message")
                msg = list(self.assistant.conversation.get_messages())[-1]


        self.toggle_lock()

        preprompt, user_msg, ai_msg = msg.get_ui(chat_submit=self.chat_submit)


        self.ui_main_content.content = self.md_chat_generator(
            self.assistant.conversation
        )
        self.page.update()

        buffer = msg.ai_response

        # Start generation with the msg
        # msg.ai_response = ""
        # msg.save()
        msg.ai_response = msg.ai_response.strip("\n").strip(" ").strip("\n")
        msg.save()
        generator = self.assistant.chatbot(msg, enable_history=ori_msg)

        tstart = time()
        for char in generator:
            # print(char)
            print(".", end="")
            buffer += char.replace("\n", "  \n")
            sec = str(time() - tstart).split(".")[0]
            word_count = len(buffer.split(" "))

            # msg.ai_response = buffer
            # msg.save()

            preprompt, user_msg, ai_msg = msg.get_ui(chat_submit=self.chat_submit)
            (
                left_arrow,
                ai_avatar,
                ai_text,
                ai_text2,
                ai_info,
                right_arrow,
            ) = ai_msg.content.controls
            ai_info.content.controls[1].value = f"{word_count} w / {sec}s"

            tindex = self.get_ui_idx_from_message(msg)

            if preprompt:
                self.lview.controls[tindex - 2] = preprompt
            self.lview.controls[tindex - 1] = user_msg
            self.lview.controls[tindex] = ai_msg

            self.page.update()

        # conv.response = buffer
        print()

        self.toggle_lock()


    def md_chat_generator(self, data):
        final_column = self.lview
        final_column.controls = []

        for entry in data:
            _ = [
                final_column.controls.append(ui_ele)
                for ui_ele in entry.get_ui(chat_submit=self.chat_submit)
                if ui_ele
            ]

        return final_column

    def load_chat_from_conversation(self, entry: Conversation):
        entry_id = str(entry.id)
        data: list[Message] = self.assistant.load_chat(entry_id)
        res = []

        for msg in data:
            res.append(msg)

        self.lview.controls = []
        self.ui_main_content.content = self.md_chat_generator(self.assistant.conversation.get_messages())
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

    page.floating_action_button = chatui.fab()
    page.overlay.append(chatui.toggle_bottom_sheet())

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
            content=chatui.main_content,
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
