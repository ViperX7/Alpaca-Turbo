import os

from django.db import models


class AIModelFormats(models.Model):
    name = models.CharField(max_length=255)
    extension = models.CharField(max_length=255)


class AIModelSettings(models.Model):
    temperature = models.FloatField()
    top_p = models.FloatField()
    top_k = models.IntegerField()
    max_length = models.IntegerField()
    repetition_penalty = models.FloatField()
    num_return_sequences = models.IntegerField()
    n_predict = models.IntegerField()
    repeat_last_n = models.IntegerField()
    seed = models.IntegerField()
    batch_size = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)


class AIModel(models.Model):
    path = models.FilePathField(path="models")
    name = models.CharField(max_length=255)
    source = models.URLField(blank=True, null=True)
    model_format = models.ForeignKey(
        "AIModelFormats", on_delete=models.CASCADE, blank=True, null=True
    )
    settings = models.ForeignKey(
        "AIModelSettings", on_delete=models.CASCADE, blank=True, null=True
    )
    version = models.CharField(max_length=255, blank=True, null=True)
    is_configured = models.BooleanField(default=False)
    is_broken = models.BooleanField(default=False)

    @staticmethod
    def list_all():
        return AIModel.objects.all()

    @staticmethod
    def add_models_from_dir(dir_path):
        model_formats = AIModelFormats.objects.values_list("extension", flat=True)
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                file_path = os.path.join(root, file)
                file_ext = os.path.splitext(file)[1]
                if file_ext in model_formats:
                    file_name = os.path.splitext(file)[0]
                    model_format = AIModelFormats.objects.get(extension=file_ext)
                    AIModel.objects.create(
                        path=file_path,
                        name=file_name,
                        model_format=model_format,
                    )
