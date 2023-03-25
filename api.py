import asyncio
# from async_generator import async_generator, yield_
from typing import List, Optional, Union
from pydantic import BaseModel
from fastapi.responses import StreamingResponse, HTMLResponse
from fastapi import FastAPI, Body, Request
from fastapi.templating import Jinja2Templates
from alpaca_turbo import Assistant


assistant = Assistant()
assistant.prep_model()

templates = Jinja2Templates(directory="templates")


app = FastAPI()


class Attachment(BaseModel):
    image: bytes


# TODO support attachments: Communication = Union[str, Attachment]
Communication = str


class Message(BaseModel):
    role: str
    content: Communication


class CompletionRequest(BaseModel):
    model: Optional[str]
    prompt: Union[Communication, List[Message]]
    max_tokens: Optional[int]
    temperature: Optional[float]
    stop: Optional[Union[str, List[str]]]


class CompletionResponseChoice(BaseModel):
    text: Communication
    finish_reason: Optional[str]


class CompletionResponse(BaseModel):
    choices: List[CompletionResponseChoice]


class Model:
    def get_completion(self, model, prompt, max_tokens, temperature, stop) -> str:
        res = ""
        for char in assistant.ask_bot(prompt):
            res += char
        return res

    def get_completion_tokens(self, model, prompt, max_tokens, temperature, stop):
        for char in assistant.ask_bot(prompt):
            yield char


model = Model()


@app.get("/", response_class=HTMLResponse)
async def read_item(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/completions", response_model=CompletionResponse)
async def completions(request: CompletionRequest):
    text = model.get_completion(
        request.model, request.prompt, request.max_tokens, request.temperature, request.stop)
    return CompletionResponse(choices=[CompletionResponseChoice(text=text)])


@app.post("/streams")
async def streams(request: CompletionRequest):
    def completion_token_generator():
        for token in model.get_completion_tokens(request.model, request.prompt, request.max_tokens, request.temperature, request.stop):
            completion_response = CompletionResponse(
                choices=[CompletionResponseChoice(text=token)])
            yield f"data: {completion_response.json()}\n\n"

    return StreamingResponse(completion_token_generator())

# Run using uvicorn api:app --reload
# This will start a local development server at http://127.0.0.1:8000. You can access the auto-generated documentation for your API at http://127.0.0.1:8000/docs.
