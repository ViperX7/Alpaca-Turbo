# Alpaca-Turbo

![Licence](https://img.shields.io/github/license/ViperX7/Alpaca-Turbo) 

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/ViperX7/Alpaca-Turbo)](https://github.com/ViperX7/Alpaca-Turbo/releases) ![Commits/month](https://img.shields.io/github/commit-activity/m/ViperX7/Alpaca-Turbo)

![Contributors](https://img.shields.io/github/contributors/ViperX7/Alpaca-Turbo) ![Downloads](https://img.shields.io/github/downloads/ViperX7/Alpaca-Turbo/total)
[![Discord](https://img.shields.io/discord/1088190461816086660?label=Discord&logo=discord&logoColor=white&color=ff69b4)](https://discord.gg/pm4JzCBHNn)



Alpaca-Turbo is a frontend to use large language models that can be run locally without much setup required. It is a user-friendly web UI for the llama.cpp , with unique features that make it stand out from other implementations. The goal is to provide a seamless chat experience that is easy to configure and use, without sacrificing speed or functionality.

## 📝 Example views


https://user-images.githubusercontent.com/38191717/234747316-2e8d5f55-73f2-4f42-ad9a-11114de1825b.mp4



## 📦 Installation Steps

### 📺 Video Instructions
- ToDo
- ToDo

#### 🐳 Using Docker (only Linux is supported with docker)
- ToDo


#### 🪟 Using Windows (standalone or miniconda) AND Mac M1/M2 (using miniconda)

> #### For Windows users we have a [oneclick standalone launcher - Alpaca-Turbo.exe](https://github.com/ViperX7/Alpaca-Turbo/releases/latest).

1. Links for installing miniconda:
    - [Windows](https://repo.anaconda.com/miniconda/Miniconda3-latest-Windows-x86_64.exe) 
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
   conda create -n alpaca_turbo python=3.10 -y
   conda activate alpaca_turbo
   pip install -r requirements.txt
   python app.py
   ```

9. ready to interact

#### Directly installing with Pip
just get the latest release unzip and then run 

```
pip install -r requirements.txt
python app.py
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

## 💁 Contributing

As an open source project in a rapidly developing field, I am open to contributions, whether it be in the form of a new feature, improved infra, or better documentation.

For detailed information on how to [contribute](.github/CONTRIBUTING.md).

## 🙌 Credits

- [ggerganov/LLaMA.cpp](https://github.com/ggerganov/LLaMA.cpp) For their amazing cpp library
- [antimatter15/alpaca.cpp](https://github.com/antimatter15/alpaca.cpp) For initial versions of their chat app
- [cocktailpeanut/dalai](https://github.com/cocktailpeanut/dalai) For the Inspiration
- MetaAI for the LLaMA models
- Stanford for the alpaca [models](https://github.com/tatsu-lab/stanford_alpaca)

## 🌟 History
[![Star History Chart](https://api.star-history.com/svg?repos=ViperX7/Alpaca-Turbo&type=Date)](https://star-history.com/#ViperX7/Alpaca-Turbo&Date)
