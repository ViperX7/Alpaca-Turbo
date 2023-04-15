import os

from django.db import models


class AIModelFormat(models.Model):
    name = models.CharField(max_length=255)
    extension = models.CharField(max_length=255)

    def __str__(self):
        return self.name


class AIModelSetting(models.Model):
    temperature = models.FloatField()
    top_p = models.FloatField()
    top_k = models.IntegerField()
    repetition_penalty = models.FloatField()
    n_predict = models.IntegerField()
    repeat_last_n = models.IntegerField()
    seed = models.IntegerField()
    batch_size = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)


class AIModel(models.Model):
    path = models.FilePathField(path="models")
    name = models.CharField(max_length=255)
    source = models.URLField(blank=True, null=True)
    author = models.CharField(max_length=255, blank=True, null=True)
    model_format = models.ForeignKey(
        "AIModelFormat", on_delete=models.CASCADE, blank=True, null=True
    )
    settings = models.ForeignKey(
        "AIModelSetting", on_delete=models.CASCADE, blank=True, null=True
    )
    version = models.CharField(max_length=255, blank=True, null=True)
    is_configured = models.BooleanField(default=False)
    is_broken = models.BooleanField(default=False)

    @staticmethod
    def list_all():
        return AIModel.objects.all()

    @property
    def model_size(self):
        size = str(os.path.getsize(self.path) / (1024 * 1024 * 1024))

        return size[: size.find(".") + 3] + " GB"

    @staticmethod
    def add_models_from_dir(dir_path):
        model_formats = AIModelFormat.objects.values_list("extension", flat=True)
        model_formats = list(model_formats)
        new_models = []
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                file_path = os.path.join(root, file)
                file_ext = os.path.splitext(file)[1]
                if file_ext in model_formats:
                    file_name = os.path.splitext(file)[0]
                    model_format = AIModelFormat.objects.get(extension=file_ext)
                    if not AIModel.objects.filter(path=file_path).exists():
                        obj = AIModel.objects.create(
                            path=file_path,
                            name=file_name,
                            model_format=model_format,
                        )
                        new_models.append(obj)
        _ = [obj.save() for obj in new_models]
        return [obj.path for obj in new_models]

    def set_settings(
        self,
        temperature,
        top_p,
        top_k,
        repetition_penalty,
        n_predict,
        repeat_last_n,
        seed,
        batch_size,
    ):
        """
        Sets the settings of the AI model.
        If a settings object already exists, it will update the existing object.
        If not, it will create a new settings object.
        """

        print(temperature)
        print("||||||||||||||||||||||||||||||||||||||")
        # Check if a settings object already exists for this AI model.
        print(self.settings)

        if self.settings:
            print("kkk")
            settings = self.settings
            # Set the settings fields.
            settings.temperature = temperature
            settings.top_p = top_p
            settings.top_k = top_k
            settings.repetition_penalty = repetition_penalty
            settings.n_predict = n_predict
            settings.repeat_last_n = repeat_last_n
            settings.seed = seed
            settings.batch_size = batch_size
        else:
            # Create a new settings object.
            settings = AIModelSetting.objects.create(
                temperature=temperature,
                top_p=top_p,
                top_k=top_k,
                repetition_penalty=repetition_penalty,
                n_predict=n_predict,
                repeat_last_n=repeat_last_n,
                seed=seed,
                batch_size=batch_size,
            )

        # Save the settings object.
        settings.save()

        # Associate the settings with this AI model.
        self.settings = settings
        self.save()
