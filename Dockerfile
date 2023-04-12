FROM python:3.8-slim


# Install pip, cmake and python
RUN apt-get update && \
    apt-get install -y --no-install-recommends cmake && \
    apt-get clean


RUN apt-get install -y --no-install-recommends curl wget vim git gcc make libc6-dev g++ unzip

RUN mkdir -p /app/models

RUN git clone https://github.com/ViperX7/llama.cpp /llama.cpp
RUN cd /llama.cpp && make
RUN cp -r /llama.cpp /main

COPY ./requirements.txt /app/
# COPY ./main /
RUN pip install --no-cache-dir -r /app/requirements.txt

# Set the working directory to /app
WORKDIR /app

# Start the webui.py file when the container is started
CMD python3 /app/api.py
