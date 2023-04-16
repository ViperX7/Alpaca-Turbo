from rest_framework import serializers
from .models import AIModel, AIModelSetting, Prompt

class AIModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = AIModel
        fields = '__all__'

class AIModelSettingSerializer(serializers.ModelSerializer):
    class Meta:
        model = AIModelSetting
        fields = '__all__'

class PromptSerializer(serializers.ModelSerializer):
    class Meta:
        model = Prompt
        fields = '__all__'

