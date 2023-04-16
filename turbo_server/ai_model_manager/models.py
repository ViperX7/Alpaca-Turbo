import os
from uuid import uuid4

import flet as ft
from django.db import models
from utils.ui_elements import (SliderWithInput, easy_content_expander,
                               get_random_color)


def save_helper(obj: models.Model, objvar: str, value):
    print("hi")
    print(value)
    setattr(obj, objvar, value)
    # print(getattr(obj,objvar))
    obj.save()



class Prompt(models.Model):
    """Prompts for the AI model."""

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)


    name = models.TextField(default="New_Preset",blank=True, null=True)
    format = models.TextField(default="### Instruction:\n\n{instruction}\n\n### Response:\n\n{response}",blank=True, null=True)
    preprompt = models.TextField(default=" Below is an instruction that describes a task. Write a response that appropriately completes the request.",blank=True, null=True)
    antiprompt = models.TextField(default="### Human:",blank=True, null=True)
    # use_bos = models.BooleanField(default=False)


    def get_ui(self):
        all_prompts = Prompt.objects.all()


        preprompt = ft.Container(
            margin = ft.margin.only(bottom=50,top=10),
            padding=0,
            content= ft.TextField(value=self.preprompt,bgcolor="#8855aa",label="Preprompt",multiline=True,min_lines=4,on_change=lambda x : save_helper(self,"preprompt",x.control.value))
        )
        fmt = ft.Container(
            margin = ft.margin.only(bottom=50),
            padding=0,
            content= ft.TextField(value=self.format,bgcolor="#8855aa",label="Format",multiline=True,min_lines=7,on_change=lambda x : save_helper(self,"format",x.control.value))
        )

        antiprompt = ft.Container(
            margin = ft.margin.only(bottom=50),
            padding=0,
            content= ft.TextField(value=self.antiprompt,bgcolor="#8855aa",label="Antiprompt",on_change=lambda x : save_helper(self,"antiprompt",x.control.value))
        )




        prompting_group = ft.Container(

            margin = 0,
            padding=0,
            content= ft.Column(
                scroll=True,
                alignment=ft.MainAxisAlignment.SPACE_EVENLY,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=10,

                controls=[
                preprompt,
                fmt,
                antiprompt,
                ]

        )
        )

        return prompting_group





class AIModelFormat(models.Model):
    name = models.CharField(max_length=255)
    extension = models.CharField(max_length=255)

    def __str__(self):
        return self.name


class AIModelSetting(models.Model):

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)


    temperature = models.FloatField(default=0.7)
    top_p = models.FloatField(default=0.99)
    top_k = models.IntegerField(default=200)
    repetition_penalty = models.FloatField(default=1.0)
    batch_size = models.IntegerField(default=256)

    n_predict = models.IntegerField(default=1000)
    repeat_last_n = models.IntegerField(default=512)
    seed = models.IntegerField(default=-1)

    created_at = models.DateTimeField(auto_now_add=True)

    def get_ui(self):
        print("JJJJJJJJJJJJJJJJ")
        temp = SliderWithInput(
            label="Temperature",
            min=0,
            max=1,
            divisions=1000,
            value=self.temperature,
            callback=lambda x: save_helper(self,"temperature",x),
        )
        top_p = SliderWithInput(
            label="Top-p",
            min=0,
            max=1,
            divisions=1000,
            value=self.top_p,
            # callback=lambda x:
            # (self.top_p := x, self.save()))
        )
        top_k = SliderWithInput(
            label="Top-k",
            min=0,
            max=2048,
            divisions=2048,
            value=self.top_k,
            # callback=lambda x:
            # (self.top_k := x, self.save()))
        )
        n_predict = SliderWithInput(
            label="N Predict",
            min=0,
            max=1000,
            divisions=1000,
            value=self.n_predict,
            # callback=lambda x:
            # (self.n_predict := x, self.save()))
        )
        repete_last_n = SliderWithInput(
            label="Repeat last N",
            min=0,
            max=1000,
            divisions=1000,
            value=self.repeat_last_n,
            # callback=lambda x:
            # (self.repeat_last_n := x, self.save()))
        )
        seed = SliderWithInput(
            label="Seed",
            min=-1,
            max=100000,
            divisions=100001,
            value=self.seed,
            # callback=lambda x:
            # (self.seed := x, self.save()))
        )
        batch_size = SliderWithInput(
            label="Batch Size",
            min=0,
            max=1000,
            divisions=1000,
            value=self.batch_size,
            # callback=lambda x:
            # (self.batch_size := x, self.save()))
        )

        repete_pen = SliderWithInput(
            label="Repeat Penalty",
            min=0,
            max=2,
            divisions=100,
            value=self.repetition_penalty,
            # callback=lambda x: (self.repetition_penalty := x, self.save()))
        )

        param_group = ft.Container(
            margin=ft.margin.only(top=10),
            padding=0,
            content=ft.Column(
                expand=True,
                alignment=ft.MainAxisAlignment.START,
                horizontal_alignment=ft.CrossAxisAlignment.START,
                spacing=10,
                controls=[
                    temp.getui(),
                    top_p.getui(),
                    top_k.getui(),
                    repete_pen.getui(),
                    n_predict.getui(),
                    repete_last_n.getui(),
                    seed.getui(),
                    batch_size.getui(),
                ],
                scroll=True,
            ),
        )

        return param_group


class AIModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)

    path = models.FilePathField(path="models")
    name = models.CharField(max_length=255)
    source = models.URLField(blank=True, null=True)
    author = models.CharField(max_length=255, blank=True, null=True)
    model_format = models.ForeignKey("AIModelFormat",
                                     on_delete=models.CASCADE,
                                     blank=True,
                                     null=True)
    settings = models.ForeignKey("AIModelSetting",
                                 on_delete=models.CASCADE,
                                 blank=True,
                                 null=True)
    prompt = models.ForeignKey("Prompt",
                                 on_delete=models.CASCADE,
                                 blank=True,
                                 null=True)

    version = models.CharField(max_length=255, blank=True, null=True)
    is_configured = models.BooleanField(default=False)
    is_broken = models.BooleanField(default=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.settings:
            self.settings = AIModelSetting.objects.create()
            self.settings.save()
        if not self.prompt:
            self.prompt = Prompt.objects.create()
            self.prompt.save()

    @staticmethod
    def list_all():
        return AIModel.objects.all()

    @property
    def model_size(self):
        size = str(os.path.getsize(self.path) / (1024 * 1024 * 1024))

        return size[:size.find(".") + 3] + " GB"


    @staticmethod
    def add_models_from_dir(dir_path):
        model_formats = AIModelFormat.objects.values_list("extension",
                                                          flat=True)
        model_formats = list(model_formats)
        new_models = []
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                file_path = os.path.join(root, file)
                file_ext = os.path.splitext(file)[1]
                if file_ext in model_formats:
                    file_name = os.path.splitext(file)[0]
                    model_format = AIModelFormat.objects.get(
                        extension=file_ext)
                    if not AIModel.objects.filter(path=file_path).exists():
                        obj = AIModel.objects.create(
                            path=file_path,
                            name=file_name,
                            model_format=model_format,
                        )
                        new_models.append(obj)
        _ = [obj.save() for obj in new_models]
        return [obj.path for obj in new_models]


    def ui_header(self):
        """ Header with model information

        Returns:
            UI with model information
        """
        head_bar = easy_content_expander(
            vexpand=False,
            bgcolor="#445566",
            content=ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    ft.Column(
                        alignment=ft.MainAxisAlignment.START,
                        horizontal_alignment=ft.CrossAxisAlignment.START,
                        controls=[
                            ft.TextField(
                                # expand=True,
                                value=self.name,
                                content_padding=0,
                                text_size=30,
                                border_color=ft.colors.TRANSPARENT,
                                on_change=lambda x: save_helper(self,"name",x.control.value),
                                         ),
                            ft.Text(f"Path:   {self.path if self.path else 'Unknown' }"),
                            ft.Text(f"Size: {self.model_size} "),
                            ft.Text(f"Source:   {self.source if self.source else 'Unknown' }"),
                            ft.Text(f"Publisher:   {self.author if self.author else 'Unknown' }"),
                        ]
                    ),
                    ft.Column(
                        alignment=ft.MainAxisAlignment.CENTER,
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        controls=[

                            ft.Icon(
                                name=ft.icons.CHECK_CIRCLE if  self.is_configured else ft.icons.WARNING_SHARP,
                                color=ft.colors.GREEN_400 if self.is_configured else ft.colors.YELLOW_400,
                                size=80,
                            ),
                            ft.Text("Ready" if self.is_configured else "Not Ready"),
                        ]
                    ),
                ]
            )
        )
        return head_bar


    def ui_list_repr(self,refresh_call,model_settings):
        list_unit = ft.Container(
                bgcolor="#232343",
                content=ft.Row(
                    controls=[
                        ft.Container(
                            expand=True,
                            content=ft.Row(
                                controls=[
                                    ft.Container(
                                        content=ft.Icon(
                                            name=ft.icons.CHECK_CIRCLE if  self.is_configured else ft.icons.WARNING_SHARP,
                                            color=ft.colors.GREEN_400 if self.is_configured else ft.colors.YELLOW_400,
                                        ),
                                    ),
                                    ft.Container(
                                        expand=True,
                                        content=ft.Text(self.name),
                                    ),
                                    ft.Container(
                                        expand=True,
                                        alignment=ft.alignment.center,
                                        content=ft.Text(self.model_size),
                                    ),
                                    ft.Container(
                                        expand=True,
                                        alignment=ft.alignment.center,
                                        content=ft.Text(self.model_format),
                                    ),

                                ]
                            )
                        ),
                        ft.Container(
                            # bgcolor=get_random_color(),
                            content=ft.Row(
                                controls=[
                                    ft.IconButton(icon=ft.icons.EDIT,icon_color="blue"),
                                    ft.IconButton(icon=ft.icons.DELETE,icon_color=ft.colors.RED_900, on_click=lambda x: [self.delete(),refresh_call()]),
                                    ft.IconButton(icon=ft.icons.SETTINGS,icon_color=ft.colors.ORANGE_400,on_click=model_settings(self)),
                                ]
                            ),
                            border_radius=20
                        ),
                    ]

                ),
                margin=0,
                padding=20,
            )



        return  list_unit





