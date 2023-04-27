import flet as ft
from ai_model_manager.models import Prompt, SliderWithInput
from alpaca_turbo import AIModel, Assistant, Conversation, Message
from utils.ui_elements import easy_content_expander, put_center


def loading_progress(state):
    "add progress loader"
    return ft.Row(
        alignment=ft.MainAxisAlignment.CENTER,
        vertical_alignment=ft.CrossAxisAlignment.CENTER,
        controls=[ft.ProgressRing(), ft.Text("Loading model please wait ... ")]
        if state == "loading"
        else [ft.Icon(ft.icons.CHECK, color="green"), ft.Text("Model loaded")],
    )


def model_selector(assistant: Assistant, callback=lambda: None):
    """Model loading UI"""
    model_options = [
        ft.dropdown.Option(model.id, model.name) for model in AIModel.objects.all()
    ]

    prompt_options = [
        ft.dropdown.Option(prompt.id, prompt.name) for prompt in Prompt.objects.filter(is_preset=True)
    ]

    prompt_selector = ft.Container(
        width=500,
        bgcolor=ft.colors.BLUE_GREY,
        content=ft.Dropdown(
            width=500,
            hint_text="Use Model Default",
            options=prompt_options,
            # value=prompt_options[0].key,
            on_change=lambda x: [
                setattr(
                    assistant,
                    "prompt",
                    Prompt.objects.filter(id=x.control.value).first(),
                ),
                model_selection_screen.update(),
            ],
        ),
    )

    if len(model_options) == 0:
        model_selection_screen = put_center(
            ft.Text(
                "No Models can be located. Please Import models from settings",
            )
        )
    else:
        model_selection_screen = ft.Container(
            bgcolor="#112233",
            expand=True,
            content=ft.Column(
                alignment=ft.MainAxisAlignment.SPACE_EVENLY,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    prompt_selector,
                    ft.Container(
                        alignment=ft.alignment.center,
                        # bgcolor="blue",
                        content=ft.Row(
                            alignment=ft.MainAxisAlignment.CENTER,
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            controls=[
                                ft.Dropdown(
                                    width=500,
                                    # label="Model",
                                    # hint_text="Select model",
                                    options=model_options,
                                    value=model_options[0].key,
                                    on_change=lambda x: [
                                        model_selection_screen.content.controls.pop()
                                        if len(model_selection_screen.content.controls)
                                        > 1
                                        else None,
                                        setattr(
                                            assistant,
                                            "model",
                                            AIModel.objects.filter(
                                                id=x.control.value
                                            ).first(),
                                        ),
                                        model_selection_screen.content.controls.append(
                                            loading_progress("loading")
                                        ),
                                        model_selection_screen.update(),
                                        assistant.load_model(),
                                        model_selection_screen.content.controls.pop(),
                                        model_selection_screen.content.controls.append(
                                            loading_progress("loaded")
                                        ),
                                        callback(),
                                        model_selection_screen.update(),
                                    ],
                                ),
                                ft.IconButton(
                                    icon=ft.icons.SETTINGS,
                                ),
                            ],
                        ),
                    ),
                    ft.Container(
                        width=500,
                        alignment=ft.alignment.center,
                        content=SliderWithInput(
                            label="Threads",
                            min=1,
                            max=8,
                            divisions=7,
                            value=4,
                            callback=lambda x: setattr(assistant, "threads", x),
                        ).getui(),
                    ),
                ],
            ),
        )

    return model_selection_screen
