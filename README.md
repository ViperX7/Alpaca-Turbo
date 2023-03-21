# Alpaca-Turbo: A Fast and Configurable Language Model-Based Chat UI

Alpaca-Turbo is a user-friendly web UI for the alpaca.cpp language model based on llama,  
with unique features that make it stand out from other implementations.

The goal is to provide a seamless chat experience that is easy to configure and use, without sacrificing speed or functionality.

## Out of the box ready for conversation

We invite you to try Alpaca-Turbo today and experience the difference for yourself.

Screenshot showing ability to remember previous part of conversation
![webui](https://user-images.githubusercontent.com/38191717/226487153-53086d64-f260-4d6e-8460-2456e72158f0.png)

Web UI to run alpaca model locally
![image](https://user-images.githubusercontent.com/38191717/226486832-9c774493-948a-4f90-96c9-695cee44b4c3.png)
![image](https://user-images.githubusercontent.com/38191717/226486862-2d59c18f-7b7a-4a9a-a54e-a3b3a0fd29ba.png)


## Try It Out!

To get started with Alpaca-Turbo, simply clone our repository and run the following commands:

```bash
git clone https://github.com/your-username/Alpaca-Turbo.git
cd Alpaca-Turbo
pip install -r requirements.txt
python webui.py
```

## Features

- **Easy Configuration:** Our UI provides a simple way to configure the bot persona and prompt style, allowing you to personalize your chatbot to your liking.
- **Lightning Fast Generation:** Alpaca-Turbo keeps the model in memory, which makes subsequent generations lightning fast, without the need to reload the model for every generation.
- **Persistent Configuration:** We understand the importance of saving your preferences, which is why our UI remembers changes between restarts, ensuring you don't have to go through the setup process every time you want to use it.
- **Seamless Chat Experience:** Our web UI ensures that the chat continues even if you restart the script that is running in the background, providing you with a seamless chat experience.
- **User-Friendly Interface:** We've designed our UI to be easy to use, with a simple interface that doesn't require any manual intervention. You can start chatting with our chatbot right away, without any complicated setup.
- **No Endless Printing:** One common problem with other chat UIs is that the bot keeps on printing stuff without stopping. That's not the case with Alpaca-Turbo. We've taken steps to ensure that the chatbot only prints when it has something to say.
- **History Mode:** Our bot has a history mode that remembers previous conversations, allowing for more personalized and engaging conversations.


# CREDITS

- [ggerganov/llama.cpp](https//github.com/ggerganov/llama.cpp) For their amazing cpp library
- [cocktailpeanut/dalai](https://github.com/cocktailpeanut/dalai) For the Inspiration
- MetaAI for the Llama models
- Stanford for the alpaca [models](https://github.com/tatsu-lab/stanford_alpaca) 


