from django.contrib import admin
from .models import Conversation, Message

class MessageInline(admin.StackedInline):
    model = Message
    extra = 0

class ConversationAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'created_at')
    inlines = [MessageInline]

class MessageAdmin(admin.ModelAdmin):
    list_display = ('conversation_id', 'index', 'user_request', 'ai_response')

admin.site.register(Conversation, ConversationAdmin)
admin.site.register(Message, MessageAdmin)

