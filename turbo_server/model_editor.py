import os
from random import choice

import django
import flet as ft
from flet import *
from flet import (ClipBehavior, Column, Container, CrossAxisAlignment, Image,
                  ListTile, MainAxisAlignment, Markdown, OutlinedButton, Page,
                  Row, Slider, Text, alignment, border, colors)
from rich import print as eprint

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "turbo_server.settings")
django.setup()

from ai_model_manager.models import AIModel

# from ai_model_manager.models import AIModel


class SliderWithInput:
    def __init__(self, label="",min=0,max=100,divisions=100,value=None) -> None:
        self.input = TextField(on_change=self.input_changed,border_color=ft.colors.TRANSPARENT,bgcolor="#3c507a",value=value)
        self.slider = Slider(min=min,max=max,divisions=divisions,on_change=self.slider_changed,value=value)
        self._value = 0
        self.color = "#435782"


        self.ui  = Container(
            bgcolor=self.color,
            content=Row(
            alignment=MainAxisAlignment.SPACE_BETWEEN,
            controls=[
                    Container(
                    expand=True,
                    content=Column(
                            controls=[
                                Container(
                                    margin=5,


                                    content=Text(label)
                                ),
                                self.slider
                            ]
                        ),
                ),
                Container(
                    # expand=True,
                    width=100,
                    content=self.input,
                ),
            ]
        )




        )

    def input_changed(self,_):
        new_val = float(self.input.value)
        if self.slider.max < new_val:
            self.slider.max = new_val
        self.value = new_val
        
        self.slider.value = self._value
        self.slider.update()


    def slider_changed(self,_):
        self.value = self.slider.value
        self.input.value = self._value

        self.input.update()


    @property
    def value(self):
        """The value property."""
        return self._value

    @value.setter
    def value(self, value):
        print(type(value))

        if  isinstance(value,int) or  isinstance(value,float):
            pass
        else:
            raise ValueError("Can't use non numeric values")
        if value < self.slider.min or value > self.slider.max:
            raise ValueError("OUT of Range")

        self._value = value
        self.slider.update()
        self.input.update()

    def getui(self):
        return self.ui




class ModelSettingsUI:
    def __init__(self, model, reset_func):
        self.target_model = model
        self.reset_func = reset_func

        self.head_bar = easy_content_expander(
            vexpand=False,
            bgcolor="#445566",
            content=Row(
                alignment=MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    Column(
                        alignment=MainAxisAlignment.START,
                        horizontal_alignment=CrossAxisAlignment.START,
                        controls=[
                            Text(self.target_model.name,size=30),
                            Text(f"Size: {self.target_model.model_size} "),
                            Text(f"Source:   {self.target_model.source if self.target_model.source else 'Unknown' }"),
                            Text(f"Publisher:   {self.target_model.author if self.target_model.author else 'Unknown' }"),
                        ]
                    ),
                    Column(
                        alignment=MainAxisAlignment.CENTER,
                        horizontal_alignment=CrossAxisAlignment.CENTER,
                        controls=[

                            Icon(
                                name=ft.icons.CHECK_CIRCLE if  self.target_model.is_configured else ft.icons.WARNING_SHARP,
                                color=ft.colors.GREEN_400 if self.target_model.is_configured else ft.colors.YELLOW_400,
                                size=80,
                            ),
                            Text("Ready" if self.target_model.is_configured else "Not Ready"),
                        ]
                    ),
                ]
            )
        )

        self.actions = easy_content_expander(
            vexpand=False,
            bgcolor=ft.colors.TRANSPARENT,
            content=Row(
                alignment=MainAxisAlignment.END,
                vertical_alignment=CrossAxisAlignment.CENTER,
                controls=[
                    Container(
                        alignment=ft.alignment.top_center,
                        content=ElevatedButton(
                            "Cancel",
                            # icon=ft.icons.SAVE,
                            on_click=self.reset_func
                        ),
                    ),
                    Container(
                        alignment=ft.alignment.top_center,
                        content=ElevatedButton(
                            "Save",
                            # icon=ft.icons.DOWNLOAD,
                            on_click=self.save,

                        ),
                    )

                ]
            ),
        )

        self.vocab_size = 2048
        self.temp = SliderWithInput(label="Temperature", min=0, max=1, divisions=1000, value=0.5)
        self.top_p = SliderWithInput(label="Top-p", min=0, max=1, divisions=1000, value=0.9)
        self.top_k = SliderWithInput(label="Top-k", min=0, max=2048, divisions=2048, value=50)
        self.repete_pen = SliderWithInput(label="Repete Penalty", min=0, max=2, divisions=100, value=1.0)
        self.n_predict = SliderWithInput(label="N Predict", min=0, max=1000, divisions=1000, value=1)
        self.repete_last_n = SliderWithInput(label="Repete last N", min=0, max=1000, divisions=1000, value=1)
        self.seed = SliderWithInput(label="Seed", min=-1, max=100000, divisions=100001, value=-1)
        self.batch_size = SliderWithInput(label="Batch Size", min=0, max=1000, divisions=1000, value=256)




        self.settings_screen =  Container(
            expand=80,
            padding=40,
            content=Column(
                expand=True,
                alignment=MainAxisAlignment.START,
                horizontal_alignment=CrossAxisAlignment.START,
                spacing=10,
                controls=[
                    self.temp.getui(),
                    self.top_p.getui(),
                    self.top_k.getui(),
                    self.repete_pen.getui(),
                    self.n_predict.getui(),
                    self.repete_last_n.getui(),
                    self.seed.getui(),
                    self.batch_size.getui(),
                ],scroll=True,
            )
        )


    def get_ui(self):
        return Container(
            expand=80,
            content=Column(
                expand=True,
                alignment=MainAxisAlignment.CENTER,
                horizontal_alignment=CrossAxisAlignment.CENTER,
                spacing=0,
                controls=[
                    self.head_bar,
                    self.settings_screen,
                    self.actions,
                ],
            )
        )

    def save(self,_):
        self.target_model.set_settings(self.temp.value,self.top_p.value,self.top_k.value,self.repete_pen.value,self.n_predict.value,self.repete_last_n.value,self.seed.value,self.batch_size.value)
        self.reset_func()
 




class ModelManagerUI:
    """UI to | Install | Configure | List | models"""

    def __init__(self, page) -> None:
        self.page : ft.Page= page
        self.models_dir_picker = ft.FilePicker(on_result=lambda result:self.import_models(result.path))
        self.page.overlay.append(self.models_dir_picker)

        self.model_list_view = ft.ListView(
            expand=1,
            spacing=0,
            # padding=20,
            animate_size=20,
        )

        self.head_bar = easy_content_expander(
                        vexpand=False,
                        bgcolor="#445566",
                        content=Row(
                            alignment=MainAxisAlignment.CENTER,
                            vertical_alignment=CrossAxisAlignment.CENTER,
                            controls=[
                                Container(
                                    alignment=ft.alignment.top_center,
                                    content=ElevatedButton(
                                        "Import Models",
                                        icon=ft.icons.ADD,
                                        on_click=lambda _: self.models_dir_picker.get_directory_path(dialog_title="Select Models Directory"),
                                    ),
                                ),
                               Container(
                                    alignment=ft.alignment.top_center,
                                    content=ElevatedButton(
                                        "Download Models",
                                        icon=ft.icons.DOWNLOAD,
                                        on_click=lambda _: AIModel.add_models_from_dir("/home/utkarsh/install_scratch/Alpaca-Turbo/turbo_server/models"),

                                    ),
                                )
                            ]
                        ),
                    )



        self.side_bar = Container(
                    expand=20,
            content=easy_content_expander(ElevatedButton("Toggle content",on_click=self.open_model_settings)),
                    bgcolor=get_random_color(),
                    margin=0,padding=0,
                )

        self.main_content =  Container(
            expand=80,
            content=Column(
                expand=True,
                alignment=MainAxisAlignment.CENTER,
                horizontal_alignment=CrossAxisAlignment.CENTER,
                spacing=0,
                controls=[
                    self.head_bar,
                    Container(expand=True,content=self.model_list_view)
                ],
            )
        )

        


        self.generate_model_list()

        self.full_ui = Row(
            spacing=0,
            controls=[
                self.side_bar,
                self.main_content,
            ]
        )



    def open_model_settings(self,model):

        # reset ui to prev state
        def reset_function(_=None):
            self.full_ui.controls = self.full_ui.controls[:-1]
            self.main_content.visible = not self.main_content.visible
            self.page.update()


        # show settings page
        self.main_content.visible = not self.main_content.visible
        settings_screen  = ModelSettingsUI(model,reset_function)
        settings_screen_ui = settings_screen.get_ui()
        self.full_ui.controls.append(settings_screen_ui)


        self.page.update()

    def refresh_model_list(self):
        self.model_list_view.controls = []
        self.generate_model_list()



    def import_models(self,path):
        path_list = AIModel.add_models_from_dir(path)
        self.refresh_model_list()
        self.page.snack_bar = ft.SnackBar(
            content=Text(f"{len(path_list)} new models imported")
        )
        self.page.snack_bar.open = True
        self.page.update()

    def delete_model(self,model:AIModel):
        def delete_this(_):
            model.delete()
            self.refresh_model_list()
            self.page.update()
        return delete_this


    def model_settings(self,model:AIModel):
        def settings_this(_):
            print("iamhere")
            self.open_model_settings(model)
        return settings_this




    def generate_model_list(self):
        controller = self.model_list_view.controls
        for model in AIModel.objects.all():
            list_unit = Container(
                bgcolor="#232343",
                content=Row(
                    controls=[
                        Container(
                            expand=True,
                            content=Row(
                                controls=[
                                    Container(
                                        content=Icon(
                                            name=ft.icons.CHECK_CIRCLE if  model.is_configured else ft.icons.WARNING_SHARP,
                                            color=ft.colors.GREEN_400 if model.is_configured else ft.colors.YELLOW_400,
                                        ),
                                    ),
                                    Container(
                                        expand=True,
                                        content=Text(model.name),
                                    ),
                                    Container(
                                        expand=True,
                                        alignment=ft.alignment.center,
                                        content=Text(model.model_size),
                                    ),
                                    Container(
                                        expand=True,
                                        alignment=ft.alignment.center,
                                        content=Text(model.model_format),
                                    ),
                                    

                                ]
                            )
                        ),
                        Container(
                            # bgcolor=get_random_color(),
                            content=Row(
                                controls=[
                                    IconButton(icon=ft.icons.EDIT,icon_color="blue"),
                                    IconButton(icon=ft.icons.DELETE,icon_color=ft.colors.RED_900, on_click=self.delete_model(model)),
                                    IconButton(icon=ft.icons.SETTINGS,icon_color=ft.colors.ORANGE_400,on_click=self.model_settings(model)),
                                ]
                            ),
                            border_radius=20
                        ),
                    ]

                ),
                margin=0,
                padding=20,
            )
            controller.append(list_unit)




def get_random_color():
    return "#" + "".join([choice("0123456789ABCDEF") for _ in range(6)])


def easy_content_expander(content, vexpand=True, hexpand=True, bgcolor=None):
    """Simple function to expand stuff"""
    obj = Row(
        expand=vexpand,
        controls=[
            Container(
                bgcolor=bgcolor if bgcolor else get_random_color(),
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


    mmui = ModelManagerUI(page)

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
                        clip_behavior=ClipBehavior.ANTI_ALIAS_WITH_SAVE_LAYER,
                        content=___main_content__,
                    )
                ],
            ),
        ),
    )

    page.update()

ft.app(target=main, assets_dir="assets")
