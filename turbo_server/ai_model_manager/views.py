from django.shortcuts import render
from rest_framework import generics, viewsets
from rest_framework.decorators import APIView, action
from rest_framework.response import Response

from .models import AIModel, AIModelSetting, Prompt
from .serializers import (AIModelSerializer, AIModelSettingSerializer,
                          PromptSerializer)

# Create your views here.


class AIModelViewSet(viewsets.ModelViewSet):
    queryset = AIModel.objects.all()
    serializer_class = AIModelSerializer

    @action(detail=False)
    def list_all(self, request):
        models = AIModel.list_all()
        serializer = AIModelSerializer(models, many=True)
        return Response(serializer.data)

    @action(detail=True)
    def model_size(self, request, pk=None):
        model = self.get_object()
        return Response(model.model_size)


class AIModelSettingViewSet(viewsets.ModelViewSet):
    queryset = AIModelSetting.objects.all()
    serializer_class = AIModelSettingSerializer


class PromptViewSet(viewsets.ModelViewSet):
    queryset = Prompt.objects.all()
    serializer_class = PromptSerializer


def add_models_from_dir(request):
    dir_path = request.query_params.get("dir_path")
    res = AIModel.add_models_from_dir(dir_path)
    return Response(res)


class AddModelsFromDir(APIView):
    @csrf_exempt
    def post(self, request):
        dir_path = request.data.get("dir_path")
        res = AIModel.add_models_from_dir(dir_path)
        return Response(res)
