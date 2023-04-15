from django.contrib import admin
from .models import AIModel, AIModelFormat, AIModelSetting

# Register your models here.
data = [AIModelSetting]
_ = [admin.site.register(mod) for mod in data]


class AIModelFormatAdmin(admin.ModelAdmin):
    list_display = ('name', 'extension')

class AIModelAdmin(admin.ModelAdmin):
    list_display = ('name', 'version', 'is_configured', 'is_broken')

admin.site.register(AIModelFormat, AIModelFormatAdmin)
admin.site.register(AIModel, AIModelAdmin)
