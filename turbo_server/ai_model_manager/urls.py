from django.urls import path, include
from rest_framework import routers
from . import views

router = routers.DefaultRouter()
router.register(r'models', views.AIModelViewSet)
router.register(r'settings', views.AIModelSettingViewSet)
router.register(r'prompts', views.PromptViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('add_from_dir/', views.AddModelsFromDir.as_view(), name='add_from_dir')
]

