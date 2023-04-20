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
from flet import (ClipBehavior, Column, Container, CrossAxisAlignment, Image,
                  ListTile, MainAxisAlignment, Markdown, OutlinedButton, Page,
                  Row, Tab, Tabs, Text, alignment, border, colors)
from plugins.chatui import ChatUI
from plugins.completionui import CompletionUI
from plugins.model_editor import ModelManagerUI
from rich import print as eprint
from utils.ui_elements import get_random_color, put_center

plugins = [
    ChatUI,
    CompletionUI,
    ModelManagerUI,
]


def main(page: Page):
    """ what do you expect the main function """

    page.horizontal_alignment = "center"
    page.vertical_alignment = "center"
    page.theme_mode = ft.ThemeMode.DARK
    # page.window_height = 1000
    # page.window_width = 1400
    page.bgcolor = "#112233"
    page.padding = 0

    ui_units = {}
    for plugin in plugins:
        unit = plugin(page)
        ui_units[unit.name] = unit.full_ui

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


_ = ft.app(target=main, assets_dir="assets") if __name__ == "__main__" else None
