# Alpaca-Turbo

![Licence](https://img.shields.io/github/license/ViperX7/Alpaca-Turbo) 

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/ViperX7/Alpaca-Turbo)](https://github.com/ViperX7/Alpaca-Turbo/releases) ![Commits/month](https://img.shields.io/github/commit-activity/m/ViperX7/Alpaca-Turbo)

![Contributors](https://img.shields.io/github/contributors/ViperX7/Alpaca-Turbo) ![Downloads](https://img.shields.io/github/downloads/ViperX7/Alpaca-Turbo/total)
[![Discord](https://img.shields.io/discord/1088190461816086660?label=Discord&logo=discord&logoColor=white&color=ff69b4)](https://discord.gg/pm4JzCBHNn)



Alpaca-Turbo is a language model that can be run locally without much setup required. It is a user-friendly web UI for the alpaca.cpp language model based on LLaMA, with unique features that make it stand out from other implementations. The goal is to provide a seamless chat experience that is easy to configure and use, without sacrificing speed or functionality.

## 📝 Example views
### Chat Frontpage
![Alpaca-Turbo Screenshot 2](./screenshots/screenshot2.png)

### Chat functionality
![Alpaca-Turbo Screenshot 1](./screenshots/screenshot1.png)

## 📦 Installation Steps

### 📺 Video Instructions
- [Windows](https://drive.google.com/file/d/1771mvqo6LgU8El1A8-m4vxXHPE-gy91u/view?usp=sharing)
- [Mac](https://www.youtube.com/watch?v=bGcrTGsSNaY)

#### 🐳 Using Docker (only Linux is supported with docker)

**Note**: for some reason this docker container works on Linux but not on Windows

> Docker must be installed on your system

1. Download the [latest alpaca-turbo.zip from the release page](https://github.com/ViperX7/Alpaca-Turbo/releases/latest).
2. Extract the contents of the zip file into a directory named alpaca-turbo.
3. Copy your alpaca models to alpaca-turbo/models/ directory.
4. Run the following command to set everything up:
   ```
    docker-compose up
   ```
5. Visit http://localhost:7887 to use the chat interface of the chatbot.

**OR**

#### 🪟 Windows/Mac M1/M2 (miniconda)

#### For Windows users we have a [oneclick standalone launcher - Alpaca-Turbo.exe](https://github.com/ViperX7/Alpaca-Turbo/releases/latest).

1. Install miniconda 
 - [windows](https://repo.anaconda.com/miniconda/Miniconda3-latest-Windows-x86_64.exe) 
 - [Mac M1/M2](https://repo.anaconda.com/miniconda/Miniconda3-latest-MacOSX-arm64.pkg)

> - Install for all users
> - Make sure to add `c:\ProgramData\miniconda3\condabin` to your environment variables

2. Download the [latest alpaca-turbo.zip from the release page](https://github.com/ViperX7/Alpaca-Turbo/releases/latest).
3. Extract Alpaca-Turbo.zip to Alpaca-Turbo
> Make sure you have enough space for the models in the extracted location
4. Copy your alpaca models to alpaca-turbo/models/ directory.
5. Open cmd as Admin and type
   ```
   conda init
   ```
6. close that window
7. open a new cmd window in your Alpaca-Turbo dir and type
   ```
   conda create -n alpaca_turbo python=3.8 -y
   conda activate alpaca_turbo
   pip install -r requirements.txt
   python api.py
   ```
8. Visit http://localhost:7887 select your model and click change wait for the model to load
9. ready to interact

## 💁 Contributing

As an open source project in a rapidly developing field, I am open to contributions, whether it be in the form of a new feature, improved infra, or better documentation.

For detailed information on how to [contribute](.github/CONTRIBUTING.md).

## 🙌 Credits
- ggerganov/LLaMA.cpp For their amazing cpp library
- antimatter15/alpaca.cpp For initial versions of their chat app
- cocktailpeanut/dalai For the Inspiration
- MetaAI for the LLaMA models
- Stanford for the alpaca models

## 🌟 History
[![Star History Chart](https://api.star-history.com/svg?repos=ViperX7/Alpaca-Turbo&type=Date)](https://star-history.com/#ViperX7/Alpaca-Turbo&Date)
