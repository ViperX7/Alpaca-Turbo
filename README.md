# Alpaca-Turbo: A Fast and Configurable way to run alpaca -Based Chat UI and API


![Apaca1](https://user-images.githubusercontent.com/38191717/227757954-2ffe5740-55da-4c01-9954-1accdb5e37bd.png)


### [Discord](https://discord.gg/FJYphgbkt2)

Alpaca-Turbo is a user-friendly web UI for the alpaca.cpp language model based on LLaMA,  
with unique features that make it stand out from other implementations.

The goal is to provide a seamless chat experience that is easy to configure and use, without sacrificing speed or
functionality.

## Out of the box ready for conversation

We invite you to try Alpaca-Turbo today and experience the difference for yourself.

Screencast showing ability to remember previous part of conversation

https://user-images.githubusercontent.com/38191717/227249838-76ab17ce-2439-4b9d-aebb-db95d13fa457.mp4

Web UI to run alpaca model locally

* AI vs AI chat
![image](https://user-images.githubusercontent.com/38191717/227757975-b75e8260-1310-4528-8f95-f61d516f9306.png)


| ![image](https://user-images.githubusercontent.com/38191717/227250115-165240e7-1e71-4f7b-afe4-ec0691a68466.png) | ![image](https://user-images.githubusercontent.com/38191717/227250289-6f4c0697-4367-4bce-a9a1-94e47433717a.png) |
|-----------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|

## Try It Out!

#### Get the model [here](https://huggingface.co/chavinlo/alpaca-native)

To get started with Alpaca-Turbo, simply clone our repository and run the following commands:

```bash
git clone https://github.com/ViperX7/Alpaca-Turbo.git
cd Alpaca-Turbo
pip install -r requirements.txt
python webui.py
```
## How to use Alpaca-Turbo on Windows

1. Open the CMD in Windows 
![CMD](https://drive.google.com/file/d/1h3RGaMDR-chuacRxTe9o5867PY1mT-VH/view?usp=share_link)
2. Clone the github repository where the CMD is opened that means in that particular directory
![Clone Repository](https://drive.google.com/file/d/1y4nWjb6X7N-QAPqqHTelxdtLqFxs0-Aw/view?usp=share_link)
```
git clone https://github.com/ViperX7/Alpaca-Turbo.git
```
3. Go into the Alpaca-Turbo Directory
![Alpaca-Turbo Directory](https://drive.google.com/file/d/1yEUU9roB5eI1Gakzwjm4NpQFcMG-IZpo/view?usp=share_link)
```
cd Alpaca-Turbo
```
4. Now installing all the dependencies which are in the requirements.txt file
![Example Image](https://drive.google.com/file/d/1_WfyktBJvhBaxQPrRo22ieNYPEvZKIXU/view?usp=share_link)
```
pip install -r requirements.txt
```
5. If you encounter any error regarding `gradio.exe.deleteme` for this just install gradio separately
![Gradio error](https://drive.google.com/file/d/1IuOjGWg-oR1sHxBEu86vUpqtPoNe1gA-/view?usp=share_link)
```
pip install gradio
```
![Gradio Install](https://drive.google.com/file/d/19uN_ZdWHrZuQpahgXzj52lbBYPwODqtE/view?usp=share_link)
![Error Resolved](https://drive.google.com/file/d/1H49WcRFo2GBJ4mRusJFu0rv-tlJ_LDbf/view?usp=share_link)
6. Then since we are good to go this process is specifically for windows then type the following command
![startwin.py](https://drive.google.com/file/d/1uLDojTgLjfciZUbx8weth3Uu0BnWKkNn/view?usp=share_link)
```
python startwin.py
```
7. After this it will ask you to download model just hit 'y' and press enter it will take its time to download the model for you
![Model Install](https://drive.google.com/file/d/1-9Qs40vBBhO2oQt8Qt0sX-MORXH7sUNE/view?usp=share_link)
![Progress](https://drive.google.com/file/d/1fy7PnuhXF4hPuYSIlqBb-cmwQ2cuOatH/view?usp=share_link)
![Completed installation of model](https://drive.google.com/file/d/1iZ4u6ZmONG38lRd0Fk4TSYXFNuWj2v9z/view?usp=share_link)
8. Now the concluding step to run our webui of Alpaca-Turbo
![Running alpaca-turbo webui.py](https://drive.google.com/file/d/1taFz1WIo17r2pRsOQzOUkJ7KPLX2-kQ3/view?usp=share_link)
```
python webui.py
```
9. Just now go to locahost:8000 or 127.0.0.1:8000 to see your Alpaca-Turbo in Action
![Running webui](https://drive.google.com/file/d/1TSrrMy7c92EB0_MfAj1LA7ZSD3Q9HPyQ/view?usp=share_link)
![Firstlook](https://drive.google.com/file/d/1FfMohbT4clh0Sspc-pjSEk5BqG0mhuYJ/view?usp=share_link)
![Model loading logs](https://drive.google.com/file/d/1yU0L_ZBwWujSPGXM3PoGMbScx2hejc2q/view?usp=share_link)
10. If this `python webui.py` command gives any error just simply delete the `settings.dat` by typing

```
del settings.dat
```

## Using the API

Run using `uvicorn api:app --reload`

This will start a local development server at http://127.0.0.1:8000.

You can access the auto-generated documentation for your API at http://127.0.0.1:8000/docs.

Discussion around standardizing the API can be found [here](https://alexatallah.notion.site/RFC-LLM-API-Standard-c8f15d24bd2f4ab98b656f08cdc1c4fb).

## Troubleshooting

- OS error
  you need to compile https://github.com/viperx7/alpaca.cpp
  manually and place alpaca.cpp/main => Alpaca-Turbo/bin/main

## Features

- **Easy Configuration:** Our UI provides a simple way to configure the bot persona and prompt style, allowing you to
  personalize your chatbot to your liking.

- **Lightning Fast Generation:** Alpaca-Turbo keeps the model in memory, which makes subsequent generations lightning
  fast, without the need to reload the model for every generation.

- **Persistent Configuration:** We understand the importance of saving your preferences, which is why our UI remembers
  changes between restarts, ensuring you don't have to go through the setup process every time you want to use it.

- **Seamless Chat Experience:** Our web UI ensures that the chat continues even if you restart the script that is
  running in the background, providing you with a seamless chat experience.

- **User-Friendly Interface:** We've designed our UI to be easy to use, with a simple interface that doesn't require any
  manual intervention. You can start chatting with our chatbot right away, without any complicated setup.

- **No Endless Printing:** One common problem with other chat UIs is that the bot keeps on printing stuff without
  stopping. That's not the case with Alpaca-Turbo. We've taken steps to ensure that the chatbot only prints when it has
  something to say.

- **History Mode:** Our bot has a history mode that remembers previous conversations, allowing for more personalized and
  engaging conversations.

# CREDITS

- [ggerganov/LLaMA.cpp](https//github.com/ggerganov/LLaMA.cpp) For their amazing cpp library
- [cocktailpeanut/dalai](https://github.com/cocktailpeanut/dalai) For the Inspiration
- MetaAI for the LLaMA models
- Stanford for the alpaca [models](https://github.com/tatsu-lab/stanford_alpaca) 






