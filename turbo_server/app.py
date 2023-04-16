from time import time

import flet as ft
from alpaca_turbo import Assistant
from flet import *
from flet import (ClipBehavior, Column, Container, CrossAxisAlignment, Image,
                  ListTile, MainAxisAlignment, Markdown, OutlinedButton, Page,
                  Row, Text, alignment, border, colors)
from rich import print as eprint


app_color_scheme = {
    "chat_bot_resp_bg": "#111",
    "chat_user_resp_bg": "#111",
    "chat_page_bg": "#111",
    "chat_input_field_bg": "#293c3a",
    "chat_input_field_font": "#ffffff",
    "chat_input_field_placeholder": "#40414e",
}

CURRENT_CHAT_CONTENT = [
    "# sdaf\n\ndsaf",
    "## dasfasf",
    "asdfsdfa",
    "asdfsdfa",
    "asdfsdfa",
]



assistant = Assistant()
assistant.load_model()


def make_on_click_fn_load_chat(entry_id,session):
    def on_click_fn(_):
        data =  assistant.load_chat(entry_id)
        res = []
        for msg in data:
            res.append(msg.user_request)
            res.append(msg.ai_response)
        session.chat_content = res
        return res
    return on_click_fn




class ChatUI:
    def __init__(self, page) -> None:
        self.chat_title = None
        self.chat_content = []
        self.page:ft.Page = page
        ### delete chat_content date title

        self.lview = ft.ListView(
            expand=1,
            spacing=0,
            # padding=20,
            auto_scroll=True,
            animate_size=20,
        )

        self.ui_sidebar = Column(
            alignment=MainAxisAlignment.SPACE_BETWEEN,
            controls=[
                Container(
                    content=self.history_builder(True),
                    alignment=alignment.top_center,
                    height=self.page.window_height-160,
                ),
                Container(
                    Text("hi"),
                    alignment=alignment.top_center,
                    height=160,
                    bgcolor="blue",
                ),
            ],
        )
        self.ui_main_content = Container(
            content=self.md_chat_generator(self.chat_content),
            bgcolor="#112233",
            height=self.page.window_height-160,
            # width=self.page.window_width*0.8,
        )

        self.ui_input_area = Container(
            alignment=alignment.bottom_center,
            padding=10,
            bgcolor="#293040",
            height=160,
            # expand=20,

            content= Column(
            alignment=MainAxisAlignment.SPACE_AROUND,
            horizontal_alignment=CrossAxisAlignment.CENTER,
            controls=[
                OutlinedButton(
                    text="Stop Generation",
                    icon=ft.icons.STOP,
                    on_click=lambda _: assistant.stop_generation(),
                    visible=False,

                ),
                TextField(
                    width=800,
                    multiline=True,
                    bgcolor=app_color_scheme["chat_input_field_bg"],
                    border_color=ft.colors.TRANSPARENT,
                    color=app_color_scheme["chat_input_field_font"],
                    border=border.all(0),
                    shift_enter=True,
                    hint_text="Enter To Send and shift enter for new line",
                    on_submit=self.chat_submit,
                    ),
                ]
            ),

        )

    def new_chat(self,_):
        self.page.floating_action_button.disabled = True
        self.page.update()

        assistant.unload_model()
        assistant.clear_chat()
        assistant.new_chat()
        assistant.load_model()
        self.chat_content = []
        self.lview.controls = []
        self.ui_main_content.content = self.md_chat_generator(self.chat_content)
        self.ui_sidebar.controls[0].content = self.history_builder(True)
        


        self.page.floating_action_button.disabled = False

        self.page.update()


    def chat_unit(self,text,idx,timetext=""):
        unit = Container(
            content=Row(
                # expand=True,
                alignment=MainAxisAlignment.CENTER,
                controls=[
                    Container(
                        content=Image(src="./assets/alpaca.png")
                        if idx % 2
                        else Image(src="./assets/alpaca2.png"),
                        width=50,
                        height=50,
                    ),
                    Container(
                        expand=True,
                        margin=ft.margin.symmetric(horizontal=20),
                        content=Markdown(
                            extension_set="gitHubFlavored",
                            code_theme="atom-one-dark",
                            code_style=ft.TextStyle(font_family="Roboto Mono"),
                            
                            # on_tap_link=lambda e: page.launch_url(e.data),

                            value=text,
                            selectable=True,
                        ) if isinstance(text,str) else text,
                    ),
                    Container(
                        width=50,
                        content=Column(
                            alignment=MainAxisAlignment.CENTER,
                            horizontal_alignment=CrossAxisAlignment.CENTER,
                            controls=[
                            Icon(
                                name=ft.icons.ACCESS_ALARMS,
                                color=ft.colors.WHITE38,
                            ),
                            Text(timetext)
                        ])
                        ,
                    ),
                ],
            ),
                    bgcolor="#334455" if idx % 2 else "#334466",
                    padding=ft.padding.only(left=50,right=50,top=10,bottom=10),
                    margin=0
                    # width=1400,
                    # expand=True,

        )
        return unit

    def toggle_lock(self):
        stop_button, input_text_box = self.ui_input_area.content.controls

        stop_button.visible = not stop_button.visible
        input_text_box.disabled = not input_text_box.disabled
        self.page.update()



    def chat_submit(self,_):
        """ Update the interaction"""
        stop_button, input_text_box = self.ui_input_area.content.controls

        user_inp = input_text_box.value
        if user_inp:
            # update the input chat log with user input
            self.chat_content.append(input_text_box.value)
            self.ui_main_content.content.controls.append(self.chat_unit(user_inp,1))
            input_text_box.value="" # empty the input boc

            # switch from interact mode to generation mode
            self.toggle_lock()


            buffer = ""
            idx = len(self.lview.controls)
            self.lview.controls.append(self.chat_unit("Thinking...",idx+1))
            self.page.update()

            generator = assistant.send_conv("",assistant.format,user_inp)

            tstart = time()
            for char in generator:
                buffer += char.replace("\n","  \n")
                sec = str(time()-tstart).split(".")[0]
                wc = len(buffer.split(" "))
                self.lview.controls[idx] = self.chat_unit(buffer,idx+1,f"{wc} w / {sec}s")
                self.page.update()

            # conv.response = buffer
            # self.chat_content.append(conv)

            self.toggle_lock()

    def conversation2chat(self,uuid):
        self.chat_content = []
        conv = assistant.load_chat(uuid)
        print(conv)
        print("-----")
        eprint(conv)
        print("-----")





    def md_chat_generator(self,data):

        final_column = self.lview

        for idx, entry in enumerate(data):
            final_column.controls.append(
                self.chat_unit(entry,idx)
                )

        return final_column


    def make_on_click_fn_load_chat(self,entry_id):
        def on_click_fn(_):
            data =  assistant.load_chat(entry_id)
            res = []
            for msg in data:
                res.append(msg.user_request)
                res.append(msg.ai_response)
            self.chat_content = res
            self.lview.controls = []
            self.ui_main_content.content = self.md_chat_generator(self.chat_content)
            self.ui_sidebar.controls[0].content = self.history_builder(False)
            self.page.update()
            return res
        return on_click_fn


    def delete_chat(self,entry_id):
        def on_click_fn(_):
            assistant.remove_chat(entry_id)
            self.ui_sidebar.controls[0].content = self.history_builder(True)
            self.page.update()
        return on_click_fn




    def history_builder(self,hide_last=False):
        data = assistant.get_conv_logs()
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
                        on_click=self.make_on_click_fn_load_chat(entry["id"]),
                        title=ft.Text(entry["title"], color=ft.colors.WHITE70),
                        # subtitle=ft.Text(entry["id"], color=ft.colors.WHITE60),
                        dense=True,
                        content_padding=ft.padding.only(15, 0, 15, 0),
                        trailing=IconButton(
                            icon=ft.icons.DELETE,
                            on_click=self.delete_chat(entry["id"]),
                            # color=ft.colors.WHITE60,
                            # size=20,
                        ),
                        leading=Icon(
                            name=ft.icons.CHAT,
                            color=ft.colors.WHITE60,
                            size=20,
                        ),
                    ),
                    bgcolor="#223344",  # if idx % 2 else "#444444",
                    padding=0,
                    margin=0.5
                    # width=1400,
                    # expand=True,
                ),
            )
        #reverse the order
        final_column.controls = final_column.controls[::-1]
        final_column.controls = final_column.controls[1:] if hide_last else final_column.controls

        return final_column




def main(page: Page):
    page.horizontal_alignment = "center"
    page.vertical_alignment = "center"
    page.theme_mode = ft.ThemeMode.DARK
    # page.window_height = 1000
    # page.window_width = 1400
    page.bgcolor = "black"
    page.padding=0
    print("---")
    print(page.window_height)
    print(page.window_width)
    print("---")

    CHATUI = ChatUI(page)

    _main_content_ = Column(
        scroll="hidden",
        expand=True,
        alignment=MainAxisAlignment.START,
        controls=[
            Row(
                alignment=MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    Container(content=CHATUI.ui_sidebar, bgcolor="#1e242e", expand=20,width=200),
                    Container(
                        bgcolor=ft.colors.RED,
                        expand=80,
                        content=Column(
                            expand=True,
                            alignment=MainAxisAlignment.SPACE_BETWEEN,
                            controls=[
                                CHATUI.ui_main_content,
                                CHATUI.ui_input_area,
                            ],
                        ),
                    ),
                ],
            )
        ],
    )

    page.floating_action_button = FloatingActionButton(icon=ft.icons.CHAT,on_click=CHATUI.new_chat)

    # set-up-some-bg-and -main-container
    # The-general-UI‘will-copy- that-of a-mobile-app
    page.add(
        # -this is just-a-bg-container
        Container(
            # width=1600,
            # height=1000,
            margin=0,padding=0,
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
                        bgcolor=ft.colors.GREEN,
                        # border_radius=40,
                        # border=border.all(0.5, "red"),
                        clip_behavior=ClipBehavior.HARD_EDGE,
                        content=_main_content_,
                    )
                ],
            ),
        ), )

    page.update()


_ = ft.app(target=main, assets_dir="assets") if __name__ == "__main__" else None
