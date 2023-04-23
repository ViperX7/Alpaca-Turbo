import flet as ft
from flet import *
import random


class SliderWithInput:
    """A slider with an input field."""

    def __init__(
        self,
        label="",
        min=0,
        max=100,
        divisions=100,
        value=None,
        callback=lambda x: x,
        ):
        """Creates a simple slider with an editable input field between a range

        Args:
            label (str): The label of the slider
            min (int|float): minimum value of the slider
            max (int|float): maximum value of the slider
            divisions (int): number of divisions in the slider
            value (int|float): initial value of the slider
            callback (function): function to call when the slider value is changed
        """

        # Given arguments
        self.label = label
        self.min = min
        self.max = max
        self.divisions = divisions
        self.callback = callback



        # Holds the value internally
        self._value = value
        self.unit_colors = {
            "input_bg": "#3c507a",
            "component_bg": "#435782",
        }

        # Init Functions
        self.getui()


    @property
    def value(self):
        """The value property."""
        return self._value

    @value.setter
    def value(self, value):
        if isinstance(value, int) or isinstance(value, float):
            pass
        else:
            raise ValueError("Can't use non numeric values")
        if value < self.slider.min or value > self.slider.max:
            raise ValueError("OUT of Range")

        self._value = value
        self.callback(value)

    def input_changed(self, _):
        """Stuff to do when input value is modified manually

        Args:
            _ (dummy): does nothing
        """
        new_val = float(self.input.value)

        self.slider.max = max(new_val, self.slider.max)

        self.value = new_val

        self.slider.value = self.value
        self.slider.update()

    def slider_changed(self, _):
        """Stuff to do when slider value is modified manually

        Args:
            _ (dummy): does nothing
        """
        self.value = self.slider.value

        self.input.value = str(self.value)
        self.input.update()

    def getui(self):
        """Returns the UI

        Returns:
            The UI
        """
        # main input field
        self.input = TextField(
            on_change=self.input_changed,
            border_color=ft.colors.TRANSPARENT,
            bgcolor=self.unit_colors["input_bg"],
            value=self.value,
        )

        # main slider
        self.slider = Slider(
            min=self.min,
            max=self.max,
            divisions=self.divisions,
            on_change=self.slider_changed,
            value=self.value,
        )

        # Final ui that will be returned
        self.final_ui = Container(
            bgcolor=self.unit_colors["component_bg"],
            content=Row(
                alignment=MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    # slider with a label
                    Container(
                        expand=True,
                        content=Column(
                            controls=[
                                Container(margin=5, content=Text(self.label)),
                                self.slider,
                            ]
                        ),
                    ),
                    # input field indicating the value
                    Container(
                        width=100,
                        content=self.input,
                    ),
                ],
            ),
        )

        return self.final_ui

    def refresh_ui(self):
        """Refresh the UI"""
        self.final_ui.update()
        self.slider.update()
        self.input.update()






cc = 0
def get_random_color():
    color = "#" + "".join([random.choice("0123456789ABCDEF") for _ in range(6)])

    return color


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


def put_center(content,bgcolor=None):
    bgcolor = bgcolor if bgcolor else get_random_color()
    ui = Container(
        margin=0,
        padding=0,
        bgcolor=bgcolor,
        alignment=ft.alignment.center,
        content=Row(
            expand=True,
            alignment=MainAxisAlignment.CENTER,
            vertical_alignment=CrossAxisAlignment.CENTER,
            controls=[
                Container(
                    expand=True,
                    alignment=ft.alignment.center,
                    bgcolor=bgcolor,
                    clip_behavior=ClipBehavior.HARD_EDGE,
                    content=content,
                )
            ],
        ),
    )

    return ui
