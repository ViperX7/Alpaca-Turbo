from chatbot.models import Conversation, Message
from django.shortcuts import render
from rest_framework import viewsets

from .serializers import ConversationSerializer, MessageSerializer


class ConversationViewSet(viewsets.ModelViewSet):
    queryset = Conversation.objects.all()
    serializer_class = ConversationSerializer


class MessageViewSet(viewsets.ModelViewSet):
    queryset = Message.objects.all()
    serializer_class = MessageSerializer


def index(request):
    return render(request, "chatbot/index.html")


def room(request, room_name):
    return render(request, "chatbot/room.html", {"room_name": room_name})
