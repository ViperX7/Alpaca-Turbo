"""
Centralized Seralizers
"""
from ai_model_manager.models import AIModel, AIModelSetting, Prompt
from chatbot.models import Conversation, Message
from rest_framework import serializers


class AIModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = AIModel
        fields = "__all__"


class AIModelSettingSerializer(serializers.ModelSerializer):
    class Meta:
        model = AIModelSetting
        fields = "__all__"


class PromptSerializer(serializers.ModelSerializer):
    class Meta:
        model = Prompt
        fields = "__all__"


class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = "__all__"


class ConversationSerializer(serializers.ModelSerializer):
    messages = MessageSerializer(many=True, read_only=True)

    class Meta:
        model = Conversation
        fields = "__all__"
