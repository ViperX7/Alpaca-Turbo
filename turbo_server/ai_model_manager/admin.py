from django.contrib import admin
from .models import AIModel, AIModelSettings

# Register your models here.
data = [AIModelSettings,AIModel]
_ = [admin.site.register(mod) for mod in data]
