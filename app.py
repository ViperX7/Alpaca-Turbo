#!/bin/python3
"""
     ▄▄▄· ▄▄▌   ▄▄▄· ▄▄▄·  ▄▄·  ▄▄▄·     ▄▄▄▄▄▄• ▄▌▄▄▄  ▄▄▄▄·
    ▐█ ▀█ ██•  ▐█ ▄█▐█ ▀█ ▐█ ▌▪▐█ ▀█     •██  █▪██▌▀▄ █·▐█ ▀█▪▪
    ▄█▀▀█ ██▪   ██▀·▄█▀▀█ ██ ▄▄▄█▀▀█      ▐█.▪█▌▐█▌▐▀▀▄ ▐█▀▀█▄ ▄█▀▄
    ▐█ ▪▐▌▐█▌▐▌▐█▪·•▐█ ▪▐▌▐███▌▐█ ▪▐▌     ▐█▌·▐█▄█▌▐█•█▌██▄▪▐█▐█▌.▐▌
     ▀  ▀ .▀▀▀ .▀    ▀  ▀ ·▀▀▀  ▀  ▀      ▀▀▀  ▀▀▀ .▀  ▀·▀▀▀▀  ▀█▄▀▪

https;//github.comViperX7/Alpaca-Turbo
"""
import flet as ft
from alpaca_turbo import AIModel, Assistant
from chatui import ChatUI
from completionui import CompletionUI
from flet import (ClipBehavior, Column, Container, CrossAxisAlignment, Image,
                  ListTile, MainAxisAlignment, Markdown, OutlinedButton, Page,
                  Row, Tab, Tabs, Text, alignment, border, colors)
from model_editor import ModelManagerUI
from rich import print as eprint
from utils.ui_elements import get_random_color


def put_center(content):
    ui = Container(
        margin=0,
        padding=0,
        bgcolor=get_random_color(),
        alignment=ft.alignment.center,
        content=Row(
            expand=True,
            alignment=MainAxisAlignment.CENTER,
            vertical_alignment=CrossAxisAlignment.CENTER,
            controls=[
                Container(
                    expand=True,
                    alignment=ft.alignment.center,
                    bgcolor=get_random_color(),
                    clip_behavior=ClipBehavior.HARD_EDGE,
                    content=content,
                )
            ],
        ),
    )

    return ui


def main(page: Page):
    page.horizontal_alignment = "center"
    page.vertical_alignment = "center"
    page.theme_mode = ft.ThemeMode.DARK
    # page.window_height = 1000
    # page.window_width = 1400
    page.bgcolor = "#112233"
    page.padding = 0
    print("---")
    print(page.window_height)
    print(page.window_width)
    print("---")

    settings = ModelManagerUI(page)
    chatui = ChatUI(page)
    completionui = CompletionUI(page)


    ui_units = {
        "Chat": chatui.full_ui,
        "Completion": completionui.full_ui,
        "Control Center": settings.full_ui,
        "four": Text("Four"),
    }

    tab_list = []
    for name, screen in ui_units.items():
        tab_list.append(
            ft.Tab(
                text=name,
                content=Container(
                    bgcolor=get_random_color(),
                    # margin=ft.margin.only(top=10),
                    alignment=ft.alignment.center,
                    content=screen,
                ),
            )
        )

    tabs = Container(
        expand=True,
        margin=0,
        padding=0,
        content=Tabs(
            scrollable=True,
            animation_duration=300,
            tabs=tab_list,
        ),
    )

    page.add(tabs)

    page.update()


_ = (
    ft.app(target=main, assets_dir="assets")
    if __name__ == "__main__"
    else None
)
