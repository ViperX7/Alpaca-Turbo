import flet as ft
from flet import *
from flet import (ClipBehavior, Column, Container, CrossAxisAlignment, Image,
                  ListTile, MainAxisAlignment, Markdown, Page, Row, Text,
                  alignment, border, colors)

app_color_scheme = {
    "chat_bot_resp_bg": "#111",
    "chat_user_resp_bg": "#111",
    "chat_page_bg": "#111",
    "chat_input_field_bg": "#293c3a",
    "chat_input_field_font": ft.colors.WHITE70,
    "chat_input_field_placeholder": "#40414e",
}


def md_chat_generator(
        data=[
            "# sdaf\n\ndsaf", "## dasfasf", "asdfsdfa", "asdfsdfa", "asdfsdfa"
        ]):
    data = data * 3
    # final_column = Column(
    #     alignment=MainAxisAlignment.START,
    #     expand=True,
    #     spacing=0,
    # )
    final_column = ft.ListView(
        expand=1,
        spacing=0,
        # padding=20,
        auto_scroll=True,
    )

    for idx, entry in enumerate(data):
        final_column.controls.append(
            Container(
                content=Row(
                    # expand=True,
                    alignment=MainAxisAlignment.CENTER,
                    controls=[
                        Container(
                            content=Image(src="./assets/alpaca.png") if idx%2 else Image(src="./assets/alpaca2.png") ,
                            width=50,
                            height=50,
                        ),
                        Container(content=Markdown(
                            value=entry,
                            selectable=True,
                            width=800,
                        ), ),
                        Container(content=Icon(
                            name=ft.icons.ALARM,
                            color=ft.colors.WHITE38,
                        ), ),
                    ],
                ),
                bgcolor="#223344" if idx % 2 else "#334466",
                padding=10,
                margin=0
                # width=1400,
                # expand=True,
            ), )

    return final_column


def history_builder(
        data=[
            "# sdaf\n\ndsaf", "## dasfasf", "asdfsdfa", "asdfsdfa", "asdfsdfa"
        ]):
    data = data * 3
    # final_column = Column(
    #     alignment=MainAxisAlignment.START,
    #     expand=True,
    #     spacing=0,
    # )
    final_column = ft.ListView(
        expand=1,
        spacing=0,
        # padding=20,
        auto_scroll=False,
    )

    for idx, entry in enumerate(data):
        final_column.controls.append(
            Container(
                content=ListTile(
                    title=ft.Text("Chat Title", color=ft.colors.WHITE70),
                    subtitle=ft.Text("Date", color=ft.colors.WHITE60),
                    dense=True,
                    content_padding=ft.padding.only(15, 0, 15, 0),
                    trailing=Icon(
                        name=ft.icons.DELETE,
                        color=ft.colors.WHITE60,
                        size=20,
                    ),
                    leading=Icon(
                        name=ft.icons.CHAT,
                        color=ft.colors.WHITE60,
                        size=20,
                    ),
                ),
                bgcolor="#223344",  #if idx % 2 else "#444444",
                padding=0,
                margin=0
                # width=1400,
                # expand=True,
            ), )

    return final_column


def main(page: Page):
    page.horizontal_alignment = "center"
    page.vertical_alignment = "center"
    page.theme_mode = ft.ThemeMode.DARK
    page.window_height = 1000
    page.window_width = 1400
    page.bgcolor = "black"

    _sidebar_ = Column(
        alignment=MainAxisAlignment.SPACE_BETWEEN,
        controls=[
            Container(
                content=history_builder(),
                alignment=alignment.top_center,
                height=640,
            ),
            Container(
                Text("hi"),
                alignment=alignment.top_center,
                height=160,
                bgcolor="blue",
            ),
        ],
    )

    _main_content_ = Column(
        scroll="hidden",
        expand=True,
        alignment=MainAxisAlignment.START,
        controls=[
            Row(
                alignment=MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    Container(content=_sidebar_, bgcolor="#1e242e", expand=20),
                    Container(
                        bgcolor="#293040",
                        height=800,
                        expand=80,
                        content=Column(
                            expand=True,
                            alignment=MainAxisAlignment.SPACE_BETWEEN,
                            controls=[
                                Container(
                                    content=md_chat_generator(),
                                    bgcolor="#112233",
                                    expand=80,
                                ),
                                Container(
                                    content=TextField(
                                        width=800,
                                        multiline=True,
                                        bgcolor=app_color_scheme[
                                            "chat_input_field_bg"],
                                        border_color=ft.colors.TRANSPARENT,
                                        color=app_color_scheme[
                                            "chat_input_field_font"],
                                        border=border.all(0),
                                        shift_enter=True,
                                        label=
                                        "Enter To Send and shift enter for new line",
                                    ),
                                    border_radius=border_radius.all(100),
                                    alignment=alignment.bottom_center,
                                    padding=10,
                                    # bgcolor="#778232",
                                    expand=20,
                                ),
                            ],
                        ),
                    ),
                ],
            )
        ],
    )

    # set-up-some-bg-and -main-container
    # The-general-UI‘will-copy- that-of a-mobile-app
    page.add(
        # -this is just-a-bg-container
        Container(
            width=1500,
            height=800,
            # margin=100,
            bgcolor="black",
            alignment=alignment.center,
            content=Row(
                alignment=MainAxisAlignment.CENTER,
                vertical_alignment=CrossAxisAlignment.CENTER,
                controls=[
                    # main Container
                    Container(
                        width=1600,
                        height=800,
                        bgcolor=ft.colors.WHITE,
                        # border_radius=40,
                        # border=border.all(0.5, "red"),
                        clip_behavior=ClipBehavior.HARD_EDGE,
                        content=Column(
                            alignment=MainAxisAlignment.CENTER,
                            expand=True,
                            controls=[_main_content_],
                        ),
                    )
                ],
            ),
        ), )

    page.update()


ft.app(target=main, assets_dir="assets",)#view=ft.WEB_BROWSER)
