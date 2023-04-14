from random import choice
from time import time

import flet as ft
from alpaca_turbo import Assistant
from flet import *
from flet import (ClipBehavior, Column, Container, CrossAxisAlignment, Image,
                  ListTile, MainAxisAlignment, Markdown, OutlinedButton, Page,
                  Row, Text, alignment, border, colors)
from rich import print as eprint

# from ai_model_manager.models import AIModel


class ModelManager:
    """UI to | Install | Configure | List | models"""

    def __init__(self, page) -> None:
        pass


def get_random_color():
    return "#" + "".join([choice("0123456789ABCDEF") for _ in range(6)])


def easy_content_expander(content, vexpand=True, hexpand=True):
    """Simple function to expand stuff"""
    obj = Row(
        expand=vexpand,
        controls=[
            Container(
                bgcolor=get_random_color(),
                expand=hexpand,
                content=Column(controls=[content]),
                padding=ft.padding.only(top=20, bottom=20, left=20, right=20),
                margin=0,
            )
        ],
    )

    return obj


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

    ___main_content__ = Column(
        expand=True,
        alignment=MainAxisAlignment.CENTER,
        horizontal_alignment=CrossAxisAlignment.CENTER,
        spacing=0,
        controls=[
            easy_content_expander(
                vexpand=False,
                content=Column(
                    controls=[
                        Text("jiji"),
                        Text("jiji"),
                        Text("jiji"),
                        Text("jiji"),
                    ]
                ),
            ),
            easy_content_expander(Text("ok")),
        ],
    )

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
            alignment=alignment.center,
            content=Row(
                expand=True,
                alignment=MainAxisAlignment.CENTER,
                vertical_alignment=CrossAxisAlignment.CENTER,
                controls=[
                    # main Container
                    Container(
                        expand=True,
                        bgcolor="#45323e",
                        # border_radius=40,
                        # border=border.all(0.5, "red"),
                        clip_behavior=ClipBehavior.HARD_EDGE,
                        content=___main_content__,
                    )
                ],
            ),
        ),
    )

    page.update()


ft.app(target=main, assets_dir="assets")
