# Alpaca-Turbo: A Fast and Configurable Language Model-Based Chat UI and API

[Discord](https://discord.gg/FEc4sn7U)

Alpaca-Turbo is a user-friendly web UI for the alpaca.cpp language model based on LLaMA,  
with unique features that make it stand out from other implementations.

The goal is to provide a seamless chat experience that is easy to configure and use, without sacrificing speed or
functionality.

## Out of the box ready for conversation

We invite you to try Alpaca-Turbo today and experience the difference for yourself.

Screencast showing ability to remember previous part of conversation

https://user-images.githubusercontent.com/38191717/227249838-76ab17ce-2439-4b9d-aebb-db95d13fa457.mp4

Web UI to run alpaca model locally

| ![image](https://user-images.githubusercontent.com/38191717/227250115-165240e7-1e71-4f7b-afe4-ec0691a68466.png) | ![image](https://user-images.githubusercontent.com/38191717/227250289-6f4c0697-4367-4bce-a9a1-94e47433717a.png) |
|-----------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|

## Try It Out!

To get started with Alpaca-Turbo, simply clone our repository and run the following commands:

```bash
git clone https://github.com/ViperX7/Alpaca-Turbo.git
cd Alpaca-Turbo
pip install -r requirements.txt
python webui.py
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






