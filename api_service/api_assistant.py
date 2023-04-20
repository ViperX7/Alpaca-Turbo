from alpaca_turbo import Assistant
from api_service.views_amm import AIModel
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt

ASSISTANT: Assistant = Assistant(AIModel.objects.first())


def load_model(request, uuid):
    global ASSISTANT
    ASSISTANT = Assistant(AIModel.objects.get(id=uuid))
    res = ASSISTANT.load_model()
    return JsonResponse(res,safe=False)


def unload_model(request):
    res = ASSISTANT.unload_model()
    return JsonResponse(res, safe=False)


def stop_generation(request):
    res = ASSISTANT.stop_generation()
    return JsonResponse(res, safe=False)


def new_chat(request):
    res = ASSISTANT.new_chat()
    return JsonResponse(res, safe=False)


def remove_all_chat(request):
    res = ASSISTANT.remove_all_chat()
    return JsonResponse(res, safe=False)


def load_chat(request, uuid):
    res = ASSISTANT.load_chat(uuid)
    return JsonResponse(res, safe=False)


def get_conv_logs(request):
    res = ASSISTANT.get_conv_logs()
    return JsonResponse(res, safe=False)


def remove_chat(request):
    res = ASSISTANT.remove_chat(uuid)
    return JsonResponse(res, safe=False)


def clear_chat(request, uuid):
    res = ASSISTANT.clear_chat(uuid)
    return JsonResponse(res, safe=False)


def safe_kill(request):
    res = ASSISTANT.safe_kill()
    return JsonResponse(res, safe=False)

def status(request):
    res = {}
    res['status'] = ASSISTANT.current_state
    res['is_loaded'] = ASSISTANT.is_loaded
    res['threads'] = ASSISTANT.threads
    return JsonResponse(res, safe=False)
