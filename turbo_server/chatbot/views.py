from django.shortcuts import render

# Create your views here.
from rest_framework import viewsets

from chatbot.serializers import MessageSerializer
from .models import Conversation, Message
from .serializers import ConversationSerializer

class ConversationViewSet(viewsets.ModelViewSet):
    queryset = Conversation.objects.all()
    serializer_class = ConversationSerializer

class MessageViewSet(viewsets.ModelViewSet):
    queryset = Message.objects.all()
    serializer_class = MessageSerializer
