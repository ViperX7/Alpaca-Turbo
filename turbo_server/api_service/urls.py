"""
All Apis here
"""
from django.urls import include, path
from rest_framework import routers

from . import views_amm, views_chatbot

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
]
