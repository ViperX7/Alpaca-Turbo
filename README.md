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

![CMD](https://dl.dropbox.com/s/rc6p3xl8sb46dgn/1.png?dl=0)

2. Clone the github repository where the CMD is opened that means in that particular directory

![Clone Repository](https://dl.dropbox.com/s/qmd7ie96y8o80k3/2.png?dl=0)

```
git clone https://github.com/ViperX7/Alpaca-Turbo.git
```
3. Go into the Alpaca-Turbo Directory

![Alpaca-Turbo Directory](https://dl.dropbox.com/s/64pum8vkv4gvbna/3.png?dl=0)

```
cd Alpaca-Turbo
```
4. Now installing all the dependencies which are in the requirements.txt file

![Dependencies install](https://dl.dropbox.com/s/r8tih2g3qnj54y8/4.png?dl=0)

```
pip install -r requirements.txt
```
5. If you encounter any error regarding `gradio.exe.deleteme` for this just install gradio separately

![Gradio error](https://dl.dropbox.com/s/igzsaksd81no81e/4%202nd.png?dl=0)

```
pip install gradio
```
![Gradio Install](https://dl.dropbox.com/s/vazcnlc3b37w1pe/5%202nd.png?dl=0)

![Error Resolved](https://dl.dropbox.com/s/qbasux4nobvi6lm/5%203rd.png?dl=0)
6. Then since we are good to go this process is specifically for windows then type the following command

![startwin.py](https://dl.dropbox.com/s/69h917ldziomsjp/6.png?dl=0)

```
python startwin.py
```
7. After this it will ask you to download model just hit 'y' and press enter it will take its time to download the model for you

![Model Install](https://dl.dropbox.com/s/uor22ox6h91lhut/8.png?dl=0)

![Progress](https://dl.dropbox.com/s/ftxdbe7uj75zcsc/10.png?dl=0)

![Completed installation of model](https://dl.dropbox.com/s/gel46m4gtuaizhy/11.png?dl=0)

8. Now the concluding step to run our webui of Alpaca-Turbo

![Running alpaca-turbo webui.py](https://dl.dropbox.com/s/vvmeki04jkesdng/12.png?dl=0)

```
python webui.py
```
9. Just now go to locahost:8000 or 127.0.0.1:8000 to see your Alpaca-Turbo in Action

![Running webui](https://dl.dropbox.com/s/3cd8jxs9wos47yp/13.png?dl=0)

![Firstlook](https://dl.dropbox.com/s/3lpolb29wq1moh3/14.png?dl=0)

![Model loading logs](https://dl.dropbox.com/s/7pyqksvryatx9xs/15.png?dl=0)

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
