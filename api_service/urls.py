"""
All Apis here
"""
from django.urls import include, path
from rest_framework import routers

from . import views_amm, views_chatbot, api_assistant

router = routers.DefaultRouter()
router.register(r"models", views_amm.AIModelViewSet)
router.register(r"settings", views_amm.AIModelSettingViewSet)
router.register(r"prompts", views_amm.PromptViewSet)

router.register(r"conversations", views_chatbot.ConversationViewSet)
router.register(r"messages", views_chatbot.MessageViewSet)

urlpatterns = [
    path("", include(router.urls)),

    path("utils/add_from_dir/", views_amm.AddModelsFromDir.as_view(), name="add_from_dir"),
    path("utils/websocket_test", views_chatbot.index, name="index"),
    path("utils/websocket_test/<str:room_name>/", views_chatbot.room, name="room"),

    path("chatbot/load_model/<str:uuid>", api_assistant.load_model, name="load_models"),
    path("chatbot/unload_model/", api_assistant.unload_model, name="unload_models"),
    path("chatbot/stop_generation/", api_assistant.stop_generation, name="stop_generation"),
    path("chatbot/new_chat/", api_assistant.new_chat, name="new_chat"),
    path("chatbot/remove_all_chat/", api_assistant.remove_all_chat, name="remove_all_chat"),
    path("chatbot/load_chat/<str:uuid>", api_assistant.load_chat, name="load_chat"),
    path("chatbot/get_conv_logs/", api_assistant.get_conv_logs, name="get_conv_logs"),
    path("chatbot/remove_chat/<str:uuid>", api_assistant.remove_chat, name="remove_chat"),
    path("chatbot/clear_chat/<str:uuid>", api_assistant.clear_chat, name="clear_chat"),
    path("chatbot/safe_kill/", api_assistant.safe_kill, name="safe_kill"),
]
