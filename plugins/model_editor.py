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

from ai_model_manager.models import AIModel, Prompt
from utils.ui_elements import (easy_content_expander, get_random_color,
                               put_center)

# from ai_model_manager.models import AIModel


def save_helper(obj, objvar: str, value):
    print("_-------")
    print(obj)
    print(objvar)
    print(value)
    print("_-------")
    setattr(obj, objvar, value)
    # print(getattr(obj,objvar))
    obj.save()


class ModelSettingsUI:
    name = "Settings"

    def __init__(self, model, reset_func):
        self.target_model = model
        self.reset_func = reset_func

        self.actions = easy_content_expander(
            vexpand=False,
            bgcolor=ft.colors.TRANSPARENT,
            content=Row(
                alignment=MainAxisAlignment.END,
                vertical_alignment=CrossAxisAlignment.CENTER,
                controls=[
                    # Container(
                    #     alignment=ft.alignment.top_center,
                    #     content=ElevatedButton(
                    #         "Cancel",
                    #         # icon=ft.icons.SAVE,
                    #         on_click=self.reset_func,
                    #     ),
                    # ),
                    Container(
                        alignment=ft.alignment.top_center,
                        content=ElevatedButton(
                            "Save",
                            # icon=ft.icons.DOWNLOAD,
                            on_click=self.reset_func,
                        ),
                    ),
                ],
            ),
        )

        self.settings_screen = Container(
            expand=80,
            padding=40,
            content=Tabs(
                selected_index=1,
                animation_duration=300,
                tabs=[
                    ft.Tab(
                        text="Parameters",
                        content=self.target_model.settings.get_ui(),
                    ),
                    ft.Tab(text="Prompting", content=self.target_model.prompt.get_ui()),
                    # ft.Tab(
                    #     text="Benchmark",
                    #     content=Text("Benchmark"),
                    # ),
                    # ft.Tab(
                    #     text="Stats",
                    #     content=Text("Stats"),
                    # ),
                ],
            ),
        )

    def get_ui(self):
        try:
            self.settings_screen.update()
            self.actions.update()
        except:
            pass

        return Container(
            expand=80,
            content=Column(
                expand=True,
                alignment=MainAxisAlignment.START,
                horizontal_alignment=CrossAxisAlignment.START,
                spacing=0,
                controls=[
                    self.target_model.ui_header(),
                    self.settings_screen,
                    self.actions,
                ],
            ),
        )

    def save(self, _):
        self.target_model.set_settings(
            self.temp.value,
            self.top_p.value,
            self.top_k.value,
            self.repete_pen.value,
            self.n_predict.value,
            self.repete_last_n.value,
            self.seed.value,
            self.batch_size.value,
        )
        self.reset_func()


class ModelManagerUI:
    """UI to | Install | Configure | List | models"""

    name = "Model Manager"

    def __init__(self, page) -> None:
        self.page: ft.Page = page
        self.full_ui()
        self.page.update()

    def full_ui(self):
        self.models_dir_picker = ft.FilePicker(
            on_result=lambda result: self.import_models(result.path)
        )

        self.page.overlay.append(self.models_dir_picker)

        self.model_list_view = ft.ListView(
            expand=1,
            spacing=0,
            # padding=20,
            animate_size=20,
        )

        self.head_bar = easy_content_expander(
            vexpand=False,
            bgcolor="#20354a",
            content=Row(
                alignment=MainAxisAlignment.CENTER,
                vertical_alignment=CrossAxisAlignment.CENTER,
                controls=[
                    Container(
                        alignment=ft.alignment.top_center,
                        content=ElevatedButton(
                            "Import Models",
                            icon=ft.icons.SYSTEM_UPDATE_ALT,
                            on_click=lambda _: self.models_dir_picker.get_directory_path(
                                dialog_title="Select Models Directory"
                            ),
                        ),
                    ),
                    Container(
                        alignment=ft.alignment.top_center,
                        content=ElevatedButton(
                            "Download Models",
                            icon=ft.icons.DOWNLOAD,
                            disabled=True,
                            on_click=lambda _: AIModel.add_models_from_dir(
                                "/home/utkarsh/install_scratch/Alpaca-Turbo/turbo_server/models"
                            ),
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
                    "Toggle content", on_click=self.open_model_settings
                ),
            ),
        )

        self.main_screen = Column(
            expand=True,
            alignment=MainAxisAlignment.CENTER,
            horizontal_alignment=CrossAxisAlignment.CENTER,
            spacing=0,
            controls=[
                self.head_bar,
                Container(expand=True, content=self.model_list_view),
            ],
        )

        self.main_util = Container(expand=80, content=self.main_screen)

        self.generate_model_list()

        self.main_content = Container(
            bgcolor="#112233",
            content=Row(
                spacing=0,
                controls=[
                    self.main_util,
                ],
            ),
        )

        return self.main_util

    def fab(self):
        return None

    def open_model_settings(self, model):
        # reset ui to prev state
        def reset_function(_=None):
            self.main_util.content = self.main_screen
            self.refresh_model_list()
            self.page.update()

        # show settings page
        settings_screen = ModelSettingsUI(model, reset_function)
        settings_screen_ui = settings_screen.get_ui()
        self.main_util.content = settings_screen_ui
        self.page.update()

    def refresh_model_list(self):
        self.model_list_view.controls = []
        self.generate_model_list()

    def import_models(self, path):
        path_list = AIModel.add_models_from_dir(path)
        self.refresh_model_list()
        self.page.snack_bar = ft.SnackBar(
            content=Text(f"{len(path_list)} new models imported")
        )
        self.page.snack_bar.open = True
        self.page.update()

    def model_settings(self, model: AIModel):
        def settings_this(_):
            self.open_model_settings(model)

        return settings_this

    def generate_model_list(self):
        controller = self.model_list_view.controls
        for model in AIModel.objects.all():
            list_unit = model.ui_list_repr(
                lambda: [self.refresh_model_list(), self.page.update()],
                model_settings=self.model_settings,
            )
            controller.append(list_unit)


class PromptManagerUI:
    """UI to | Install | Configure | List | Prompt"""

    name = "Prompt Manager"

    def __init__(self, page) -> None:
        self.page: ft.Page = page
        self.full_ui()
        self.page.update()

    def create_new_prompt(self):
        obj = Prompt.objects.create()
        obj.is_preset = True
        obj.save()
        return obj

    def full_ui(self):
        self.prompt_file_picker = ft.FilePicker(
            on_result=lambda result: [Prompt.import_from_json([f.path for f in result.files]),self.refresh_prompt_list()]
        )
        self.page.overlay.append(self.prompt_file_picker)

        self.prompt_list_view = ft.ListView(
            expand=1,
            spacing=0,
            # padding=20,
            animate_size=20,
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
                            "Back",
                            # icon=ft.icons.DOWNLOAD,
                            on_click=lambda _: self.refresh_prompt_list(),
                        ),
                    ),
                ],
            ),
        )

        self.head_bar = easy_content_expander(
            vexpand=False,
            bgcolor="#20354a",
            content=Row(
                alignment=MainAxisAlignment.CENTER,
                vertical_alignment=CrossAxisAlignment.CENTER,
                controls=[
                    Container(
                        alignment=ft.alignment.top_center,
                        content=ElevatedButton(
                            "Create New",
                            icon=ft.icons.ADD,
                            on_click=lambda _: [
                                setattr(
                                    self.main_util,
                                    "content",
                                    Column(
                                        alignment=MainAxisAlignment.SPACE_BETWEEN,
                                        controls=[
                                            self.create_new_prompt().get_ui(
                                                preset_mode=True
                                            ),
                                            self.actions,
                                        ],
                                    ),
                                ),
                                self.page.update(),
                            ],
                        ),
                    ),
                    Container(
                        alignment=ft.alignment.top_center,
                        content=ElevatedButton(
                            "Import Prompts",
                            icon=ft.icons.SYSTEM_UPDATE_ALT,
                            on_click=lambda _: self.prompt_file_picker.pick_files(
                                dialog_title="Import Prompt",file_type="json",allow_multiple=True,
                            ),
                        ),
                    ),
                    Container(
                        alignment=ft.alignment.top_center,
                        content=ElevatedButton(
                            "Download Prompts",
                            icon=ft.icons.DOWNLOAD,
                            disabled=True,
                            on_click=lambda _: AIModel.add_models_from_dir(
                                "/home/utkarsh/install_scratch/Alpaca-Turbo/turbo_server/models"
                            ),
                        ),
                    ),
                ],
            ),
        )

        self.main_screen = Column(
            expand=True,
            alignment=MainAxisAlignment.CENTER,
            horizontal_alignment=CrossAxisAlignment.CENTER,
            spacing=0,
            controls=[
                self.head_bar,
                Container(expand=True, content=self.prompt_list_view),
            ],
        )

        self.main_util = Container(expand=80, content=self.main_screen)

        self.generate_prompt_list()

        self.main_content = Container(
            bgcolor="#112233",
            content=Row(
                spacing=0,
                controls=[
                    self.main_util,
                ],
            ),
        )

        return self.main_util

    def fab(self):
        return None

    def open_prompt_settings(self, model):
        # reset ui to prev state
        def reset_function(_=None):
            self.main_util.content = self.main_screen
            self.refresh_prompt_list()
            self.page.update()

        # show settings page
        settings_screen = ModelSettingsUI(model, reset_function)
        settings_screen_ui = settings_screen.get_ui()
        self.main_util.content = settings_screen_ui
        self.page.update()

    def refresh_prompt_list(self):
        self.prompt_list_view.controls = []
        self.generate_prompt_list()
        self.main_util.content = self.main_screen
        self.page.update()

    def import_models(self, path):
        path_list = AIModel.add_models_from_dir(path)
        self.refresh_prompt_list()
        self.page.snack_bar = ft.SnackBar(
            content=Text(f"{len(path_list)} new models imported")
        )
        self.page.snack_bar.open = True
        self.page.update()

    def model_settings(self, model: AIModel):
        def settings_this(_):
            self.open_prompt_settings(model)

        return settings_this

    def generate_prompt_list(self):
        controller = self.prompt_list_view.controls
        for prompt in Prompt.objects.filter(is_preset=True):
            list_unit = prompt.ui_list_repr(
                refresh_call=lambda: self.refresh_prompt_list(),
                prompt_settings=lambda prompt=prompt: [
                    setattr(
                        self.main_util,
                        "content",
                        Column(
                            alignment=MainAxisAlignment.SPACE_BETWEEN,
                            controls=[prompt.get_ui(preset_mode=True), self.actions],
                        ),
                    ),
                    self.page.update(),
                ],
            )
            controller.append(list_unit)


class SettingsManager:
    """UI to | Install | Configure | List | models"""

    name = "Settings"

    def __init__(self, page) -> None:
        self.page: ft.Page = page
        self.full_ui()
        self.page.update()

    def full_ui(self):
        self.enabled_modules = {
            "Models": {
                "icon": ft.icons.ADD_BOX_SHARP,
                "module": ModelManagerUI(self.page).full_ui(),
            },
            "Prompts": {
                "icon": ft.icons.ADD_BOX_SHARP,
                "module": PromptManagerUI(self.page).full_ui(),
            },
            # "Stuff": {
            #     "icon": ft.icons.ADD_BOX_SHARP,
            #     "module": ModelManagerUI(self.page).full_ui(),
            # },
            # "Advanced": {
            #     "icon": ft.icons.ADD_BOX_SHARP,
            #     "module": ModelManagerUI(self.page).full_ui(),
            # },
        }

        elements = [
            ListTile(
                leading=ft.Icon(unit["icon"]),
                title=ft.Text(name),
                dense=True,
                on_click=lambda _, name=name, unit=unit: [
                    setattr(self.main_util, "content", unit["module"]),
                    [setattr(element, "selected", False) for element in elements],
                    setattr(
                        elements[list(self.enabled_modules.keys()).index(name)],
                        "selected",
                        True,
                    ),
                    self.page.update(),
                ],
            )
            for name, unit in self.enabled_modules.items()
        ]

        self.side_bar = Container(
            expand=20,
            bgcolor="#1e242e",
            margin=0,
            padding=0,
            content=ft.ListView(
                controls=elements,
            ),
        )

        self.main_util = Container(
            expand=80,
            content=put_center(Text("Hello")),
        )

        if self.enabled_modules:
            self.main_util.content = list(self.enabled_modules.values())[0]["module"]
            elements[0].selected = True
            self.page.update()

        self.main_content = Container(
            bgcolor="#112233",
            content=Row(
                spacing=0,
                controls=[
                    self.side_bar,
                    self.main_util,
                ],
            ),
        )

        return self.main_content

    def fab(self):
        return None


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

    ssui = SettingsManager(page)

    ___main_content__ = ssui.main_content

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
