import flet as ft
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

    if len(model_options) == 0:
        model_selection_screen = put_center(
            ft.Text(
                "No models imported import from settings",
            )
        )
    else:

        model_selection_screen = ft.Container(
            bgcolor="#112233",
            expand=True,
            content=ft.Column(
                alignment=ft.MainAxisAlignment.CENTER,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
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
                                        if len(model_selection_screen.content.controls) > 1
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
                ],
            ),
        )

    return model_selection_screen
