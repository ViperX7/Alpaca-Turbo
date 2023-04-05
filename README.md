# Alpaca-Turbo

Alpaca-Turbo is a language model that can be run locally without much setup required. It is a user-friendly web UI for the alpaca.cpp language model based on LLaMA, with unique features that make it stand out from other implementations. The goal is to provide a seamless chat experience that is easy to configure and use, without sacrificing speed or functionality.

##### [Discord](https://discord.gg/pm4JzCBHNn)

![Alpaca-Turbo Screenshot 2](./screenshots/screenshot2.png)
![Alpaca-Turbo Screenshot 1](./screenshots/screenshot1.png)

## Installation Steps

#### Using Docker (only Linux is supported with docker)

**Note**: for some reason this docker container works on linux but not on windows

> Docker must be installed on your system

1. Download the latest alpaca-turbo.zip from the release page. [here](https://github.com/ViperX7/Alpaca-Turbo/releases/)
2. Extract the contents of the zip file into a directory named alpaca-turbo.
3. Copy your alpaca models to alpaca-turbo/models/ directory.
4. Run the following command to set everything up:
   ```
     docker-compose up
   ```
5. Visit http://localhost:5000 to use the chat interface of the chatbot.

#### Windows/Mac M1/M2 (miniconda)

1. Install miniconda 
    - [windows](https://repo.anaconda.com/miniconda/Miniconda3-latest-Windows-x86_64.exe) 
    - [Mac M1/M2](https://repo.anaconda.com/miniconda/Miniconda3-latest-MacOSX-arm64.pkg)

   > - Install for all users
   > - Make sure to add `c:\ProgramData\miniconda3\condabin` to your environment variables

2. Download the latest alpaca-turbo.zip from the release page. [here](https://github.com/ViperX7/Alpaca-Turbo/releases/)
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
8. Visit http://localhost:5000 select your model and click change wait for the model to load
9. ready to interact

# CREDITS

- [ggerganov/LLaMA.cpp](https://github.com/ggerganov/LLaMA.cpp) For their amazing cpp library
- [antimatter15/alpaca.cpp](https://github.com/antimatter15/alpaca.cpp) For initial versions of their chat app
- [cocktailpeanut/dalai](https://github.com/cocktailpeanut/dalai) For the Inspiration
- MetaAI for the LLaMA models
- Stanford for the alpaca [models](https://github.com/tatsu-lab/stanford_alpaca)
