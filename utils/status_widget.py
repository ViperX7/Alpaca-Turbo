import flet as ft
import psutil

cpu_percent = psutil.cpu_percent()
ram_percent = psutil.virtual_memory().percent
print(cpu_percent)
print(ram_percent)
print("==")


def status_widget():
    stwid = ft.Container(
        ft.Column(
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            controls=[
                ft.Text("CPU"),
                ft.ProgressBar(width=400, color="blue", value=lambda:psutil.cpu_percent()//100),
                ft.Container(height=20),
                ft.Text("RAM"),
                ft.ProgressBar(width=400, color="blue", value=ram_percent/100),
            ],
        ),
        alignment=ft.alignment.center,
        height=160,
        bgcolor=ft.colors.BLUE_GREY,
        padding=20,
    )

    return stwid
