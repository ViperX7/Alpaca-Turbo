from uuid import uuid4

import flet as ft
from ai_model_manager.models import AIModel
from django.db import models


class Conversation(models.Model):
    # model_used = models.ForeignKey(AIModel, on_delete=models.CASCADE)
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    title = models.TextField()

    def __getitem__(self, index):
        messages = self.get_messages()
        if isinstance(index, slice):
            result = messages[index.start : index.stop : index.step]
        else:
            result = messages[index]
        return result

    def __setitem__(self, index, value):
        if isinstance(index, slice):
            messages = self.get_messages()
            messages[index.start : index.stop : index.step] = value
            for i, message in enumerate(messages):
                message.index = i
                message.save()
        else:
            message = self.get_messages()[index]
            message.user_request = value["user_request"]
            message.ai_response = value["ai_response"]
            message.preprompt = value["preprompt"]
            message.format = value["format"]
            message.params = value["params"]
            message.save()

    def __str__(self) -> str:
        return self.title

    def get_messages(self):
        return Message.objects.filter(conversation=self).order_by("index")

    @staticmethod
    def clear_blank():
        """remove all conversations with no messages"""
        objs = Conversation.objects.all()
        for obj in objs:
            if len(Message.objects.filter(conversation=obj)) == 0:
                obj.delete()

    @staticmethod
    def remove_all_conv():
        """Removes all conversations"""
        objs = Conversation.objects.all()
        total = len(objs)
        objs.delete()
        return total

    @staticmethod
    def get_all_conversations():
        conversations = Conversation.objects.all().values("id", "title", "created_at")
        return list(conversations)

    @property
    def lastidx(self):
        """returns the index of the last element"""
        index = 0
        last_message = (
            Message.objects.filter(conversation=self).order_by("-index").first()
        )
        if last_message:
            index = last_message.index
        return index

    def add_message(
        self, user_request, ai_response="", preprompt=None, format=None, params=None
    ):
        """Add a new message to the conversation.

        Args:
            user_request (str): prompt from the user
            ai_response (str): response from the AI
            preprompt (str): preprompt
            format (str): format for interaction
            params (): [TODO:description]

        Returns:
            Message: Message object
        """
        message = Message(
            conversation=self,
            index=-2,
            user_request=user_request,
            ai_response=ai_response,
            preprompt=preprompt,
            format=format,
            params=params,
        )
        self.append(message)
        return message

    def append(self, message):
        """Append a new message to the conversation."""
        message.conversation = self
        message.index = self.lastidx + 1
        message.save()
        if message.index == 0:
            self.title = message.user_request
            self.save()

    @staticmethod
    def ui_conversation_list(hide_last=False, select_chat_callback=lambda _: None):
        """Returns a UI listing all conversations"""
        final_column = ft.ListView(
            expand=1,
            spacing=0,
            # padding=20,
            auto_scroll=False,
        )

        for entry in Conversation.objects.all():
            final_column.controls.append(
                ft.Container(
                    content=ft.ListTile(
                        on_click=lambda _, entry=entry: select_chat_callback(entry),
                        title=ft.Text(entry.title, color=ft.colors.WHITE70),
                        subtitle=ft.Text(
                            str(entry.id), color=ft.colors.WHITE60, visible=False
                        ),
                        dense=True,
                        content_padding=ft.padding.only(15, 0, 15, 0),
                        trailing=ft.IconButton(
                            icon=ft.icons.DELETE,
                            on_click=lambda _, entry=entry: [
                                [final_column.controls.remove(unit) for unit in final_column.controls if unit.content.subtitle.value == str(entry.id)],
                                entry.delete(),
                                final_column.update(),
                            ],
                            # color=ft.colors.WHITE60,
                            # size=20,
                        ),
                        leading=ft.Icon(
                            name=ft.icons.CHAT,
                            color=ft.colors.WHITE60,
                            size=20,
                        ),
                    ),
                    bgcolor="#223344",  # if idx % 2 else "#444444",
                    padding=0,
                    margin=0.5
                    # width=1400,
                    # expand=True,
                ),
            )
        # reverse the order
        final_column.controls = final_column.controls[::-1]
        final_column.controls = (
            final_column.controls[1:] if hide_last else final_column.controls
        )

        return final_column


class Message(models.Model):
    """Message model for a conversation"""

    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE)
    index = models.PositiveIntegerField()
    user_request = models.TextField()
    ai_response = models.TextField()
    preprompt = models.TextField(max_length=512, blank=True, null=True)
    format = models.TextField(max_length=512, blank=True, null=True)
    params = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"{self.user_request}"

    def get_prompt(self):
        """Returns the user prompt after applying the format"""
        msg = []
        data = self.format.format(
            instruction=self.user_request, response=self.ai_response
        )
        msg.append(data)
        return msg
