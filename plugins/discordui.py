#!/bin/python3
"""
     ▄▄▄· ▄▄▌   ▄▄▄· ▄▄▄·  ▄▄·  ▄▄▄·     ▄▄▄▄▄▄• ▄▌▄▄▄  ▄▄▄▄·
    ▐█ ▀█ ██•  ▐█ ▄█▐█ ▀█ ▐█ ▌▪▐█ ▀█     •██  █▪██▌▀▄ █·▐█ ▀█▪▪
    ▄█▀▀█ ██▪   ██▀·▄█▀▀█ ██ ▄▄▄█▀▀█      ▐█.▪█▌▐█▌▐▀▀▄ ▐█▀▀█▄ ▄█▀▄
    ▐█ ▪▐▌▐█▌▐▌▐█▪·•▐█ ▪▐▌▐███▌▐█ ▪▐▌     ▐█▌·▐█▄█▌▐█•█▌██▄▪▐█▐█▌.▐▌
     ▀  ▀ .▀▀▀ .▀    ▀  ▀ ·▀▀▀  ▀  ▀      ▀▀▀  ▀▀▀ .▀  ▀·▀▀▀▀  ▀█▄▀▪

https;//github.comViperX7/Alpaca-Turbo
"""
import os

import django
import flet as ft
from flet import *
from flet import (ClipBehavior, Column, Container, CrossAxisAlignment, Image,
                  ListTile, MainAxisAlignment, Markdown, OutlinedButton, Page,
                  Row, Slider, Text, alignment, border, colors)
from rich import print as eprint

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "turbo_server.settings")
django.setup()

import discord
from ai_model_manager.models import AIModel, Prompt
from alpaca_turbo import Assistant, Conversation
from asgiref.sync import sync_to_async
from utils.model_selector import model_selector
from utils.ui_elements import easy_content_expander, get_random_color

# from ai_model_manager.models import AIModel


class MyClient(discord.Client):
    def __init__(self, callback, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.callback = callback

    async def on_ready(self):
        print("Logged on as", self.user)

    async def on_message(self, message):
        # don't respond to ourselves
        if message.author == self.user:
            return

        # pass message to callback function
        self.callback(message)


with open("./dtoken.txt") as f:
    DISCORD_TOKEN = f.read()


class DiscordUI:
    """Discord UI"""

    name = "Discord"

    def __init__(self, page) -> None:
        self.page: ft.Page = page
        self.models_dir_picker = ft.FilePicker(
            on_result=lambda result: self.import_models(result.path)
        )
        self.page.overlay.append(self.models_dir_picker)

        # Loading assistant
        self.assistant = Assistant()
        self.conversation = Conversation()
        self.conversation.save()
        self.model_selector = model_selector(self.assistant)

        self.discord_screen = Container(
            expand=True,
            margin=ft.margin.only(left=20, right=20),
            content=Column(
                spacing=10,
                controls=[
                    Row(
                        alignment=MainAxisAlignment.CENTER,
                        vertical_alignment=CrossAxisAlignment.START,
                        controls=[
                            Container(
                                margin=ft.margin.only(top=20),
                                height=250,
                                width=250,
                                content=ft.Image(src="./assets/alpaca.png"),
                            ),
                        ],
                    ),
                    TextField(
                        label="Enter your discord token",
                        value=DISCORD_TOKEN,
                        password=True,
                    ),
                    Container(content=self.model_selector),
                ],
            ),
        )

        self.action_bar = easy_content_expander(
            vexpand=False,
            bgcolor="#20354a",
            content=Row(
                alignment=MainAxisAlignment.CENTER,
                vertical_alignment=CrossAxisAlignment.CENTER,
                controls=[
                    Container(
                        alignment=ft.alignment.top_center,
                        content=ElevatedButton(
                            "Launch Bot",
                            icon=ft.icons.ROCKET_LAUNCH_OUTLINED,
                            on_click=lambda _: [self.launch_bot(_)],
                        ),
                    ),
                    Container(
                        alignment=ft.alignment.top_center,
                        content=ElevatedButton(
                            "Conversation",
                            icon=ft.icons.CHAT_OUTLINED,
                            on_click=lambda _: "conversation",
                        ),
                    ),
                ],
            ),
        )

        self.side_bar = Container(
            expand=20,
            bgcolor="#1e242e",
            margin=0,
            padding=0,
            content=easy_content_expander(
                bgcolor="#1e242e",
                content=ElevatedButton(
                    "Toggle content",
                ),
            ),
        )

        self.main_content = Container(
            expand=80,
            content=Column(
                expand=True,
                alignment=MainAxisAlignment.CENTER,
                horizontal_alignment=CrossAxisAlignment.CENTER,
                spacing=0,
                controls=[
                    ft.Card(
                        content=ft.Container(
                            content=ft.Column(
                                [
                                    ft.ListTile(
                                        leading=ft.Icon(ft.icons.WARNING),
                                        title=ft.Text("Notice"),
                                        subtitle=ft.Text(
                                            "This plugin doesn't works because of some sync async issue i don't want to give it any more time if someone can fix it will be great"
                                        ),
                                    ),
                                ]
                            ),
                            width=400,
                            padding=10,
                        )
                    ),
                    Container(expand=True, content=self.discord_screen),
                    self.action_bar,
                ],
            ),
        )

        self.full_ui = Container(
            bgcolor="#112233",
            content=Row(
                spacing=0,
                controls=[
                    self.side_bar,
                    self.main_content,
                ],
            ),
        )

    def callback(self, message):
        tcolumn = self.discord_screen.content.controls
        tcolumn.append(Markdown(message.content))
        msg = self.conversation.add_message(message.content)

        result = self.assistant.chatbot(msg)
        print(result)

        self.page.update()

    def launch_bot(self, _):
        print("sdafljsafdlj")
        intents = discord.Intents.default()
        intents.message_content = True

        self.dbot = MyClient(intents=intents, callback=self.callback)
        self.dbot.run(self.discord_screen.content.controls[1].value)
        print("Bot launched")


def main(page: Page):
    page.horizontal_alignment = "center"
    page.vertical_alignment = "center"

    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = "black"
    page.padding = 0

    mmui = DiscordUI(page)

    ___main_content__ = mmui.full_ui

    # set-up-some-bg-and -main-container
    # The-general-UI‘will-copy- that-of a-mobile-app
    page.add(
        # -this is just-a-bg-container
        Container(
            # width=1600,
            # height=1000,
            margin=0,
            padding=0,
            expand=True,
            # margin=100,
            bgcolor="blue",
            alignment=ft.alignment.center,
            content=Row(
                expand=True,
                alignment=MainAxisAlignment.CENTER,
                vertical_alignment=CrossAxisAlignment.CENTER,
                controls=[
                    # main Container
                    Container(
                        expand=True,
                        bgcolor="#45323e",
                        clip_behavior=ClipBehavior.ANTI_ALIAS_WITH_SAVE_LAYER,
                        content=___main_content__,
                    )
                ],
            ),
        ),
    )

    page.update()


_ = ft.app(target=main, assets_dir="assets") if __name__ == "__main__" else None
