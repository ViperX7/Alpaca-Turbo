#!/bin/python3
"""
     ▄▄▄· ▄▄▌   ▄▄▄· ▄▄▄·  ▄▄·  ▄▄▄·     ▄▄▄▄▄▄• ▄▌▄▄▄  ▄▄▄▄·
    ▐█ ▀█ ██•  ▐█ ▄█▐█ ▀█ ▐█ ▌▪▐█ ▀█     •██  █▪██▌▀▄ █·▐█ ▀█▪▪
    ▄█▀▀█ ██▪   ██▀·▄█▀▀█ ██ ▄▄▄█▀▀█      ▐█.▪█▌▐█▌▐▀▀▄ ▐█▀▀█▄ ▄█▀▄
    ▐█ ▪▐▌▐█▌▐▌▐█▪·•▐█ ▪▐▌▐███▌▐█ ▪▐▌     ▐█▌·▐█▄█▌▐█•█▌██▄▪▐█▐█▌.▐▌
     ▀  ▀ .▀▀▀ .▀    ▀  ▀ ·▀▀▀  ▀  ▀      ▀▀▀  ▀▀▀ .▀  ▀·▀▀▀▀  ▀█▄▀▪

https;//github.comViperX7/Alpaca-Turbo
"""
import sys

import flet as ft
from alpaca_turbo import AIModel, Assistant
from flet import (ClipBehavior, Column, Container, CrossAxisAlignment, Image,
                  ListTile, MainAxisAlignment, Markdown, OutlinedButton, Page,
                  Row, Tab, Tabs, Text, alignment, border, colors)
from plugins.chatui import ChatUI
from plugins.completionui import CompletionUI
from plugins.model_editor import ModelManagerUI, SettingsManager
from rich import print as eprint
from utils.ui_elements import get_random_color, put_center

plugins = [
    ChatUI,
    CompletionUI,
    SettingsManager,
]


def main(page: Page):
    """what do you expect the main function"""

    page.horizontal_alignment = "center"
    page.vertical_alignment = "center"
    page.theme_mode = ft.ThemeMode.DARK
    # page.window_height = 1000
    # page.window_width = 1400
    page.bgcolor = "#112233"
    page.padding = 0

    fab_actions = []
    ui_units = {}
    for plugin in plugins:
        unit = plugin(page)
        ui_units[unit.name] = unit.full_ui()
        fab_actions.append(unit.fab())

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
    page.floating_action_button = fab_actions[0]

    tab_changed = lambda _: [
        setattr(
            page, "floating_action_button", fab_actions[tabs.content.selected_index]
        ),
        page.update(),
    ]

    tabs = Container(
        expand=True,
        margin=0,
        padding=0,
        content=Tabs(
            scrollable=True,
            animation_duration=300,
            tabs=tab_list,
            on_change=tab_changed,
        ),
    )

    page.add(tabs)
    page.title = "Alpaca Turbo"

    page.update()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Argument parser for web server")

    parser.add_argument("--web", action="store_true", help="Enable web server")

    parser.add_argument(
        "--host", type=str, default="127.0.0.1", help="IP address to listen on"
    )
    parser.add_argument("--port", type=int, default=7887, help="Port to listen on")

    args = parser.parse_args()

    _ = ft.app(
        target=main,
        assets_dir="assets",
        name="Alpaca Turbo",
        host=args.host,
        port=args.port,
        view=ft.WEB_BROWSER if args.web else ft.FLET_APP,
    )
