#!/usr/bin/env python3

import os
import urllib.request
from rich.progress import Progress


def clear_screen():
    print("\033c")


def print_header():
    print("")
    print("   / \  | |_ __   __ _  ___ __ _  |_   _|   _ _ __| |__   ___  ")
    print("  / _ \ | | |_ \ / _` |/ __/ _` |   | || | | | |__| |_ \ / _ \ ")
    print(" / ___ \| | |_) | (_| | (_| (_| |   | || |_| | |  | |_) | (_) |")
    print("/_/   \_\_| .__/ \__,_|\___\__,_|   |_| \__,_|_|  |_.__/ \___/ ")
    print("          |_|                                                  ")
    print("")
    print("")
    print("https://github.com/ViperX7/Alpaca-Turbo/")
    print("")
    print("")
    print("")
    print("")


def download_model():
    url = "https://huggingface.co/Sosaka/Alpaca-native-4bit-ggml/resolve/main/ggml-alpaca-7b-q4.bin"
    filename = "ggml-alpaca-7b-q4.bin"

    if os.path.exists(filename):
        return

    choice = input("The model has not been downloaded. Would you like to download it now? (y/n)")
    if choice.lower() == "y":
        with Progress() as progress:
            task = progress.add_task("Downloading...", start=False)
            with urllib.request.urlopen(url) as response, open(filename, "wb") as out_file:
                file_size = int(response.headers.get("content-length", 0))
                progress.update(task, total=file_size)
                progress.start_task(task)
                downloaded = 0
                block_size = 8192
                while True:
                    buffer = response.read(block_size)
                    if not buffer:
                        break
                    out_file.write(buffer)
                    downloaded += len(buffer)
                    progress.update(task, advance=len(buffer))
                progress.remove_task(task)
    else:
        exit()


def check_filesize():
    filename = "ggml-alpaca-7b-q4.bin"
    filesize = os.path.getsize(filename)

    if filesize > 3221225472:
        return

    choice = input("The file size is less than or equal to 3GB. Do you want to redownload and delete the older file? (y/n)")
    if choice.lower() == "y":
        os.remove(filename)
        download_model()
    else:
        exit()


def main():
    clear_screen()
    print_header()
    download_model()
    check_filesize()


if __name__ == "__main__":
    main()

