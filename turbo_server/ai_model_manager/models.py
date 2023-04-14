from django.db import models



class AIModelSettings(models.Model):
    name = models.CharField(max_length=255)
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
    model_format = models.CharField(max_length=255, blank=True, null=True)
    settings = models.ForeignKey("AIModelSettings", on_delete=models.CASCADE)


    @staticmethod
    def list_all():
        return AIModel.objects.all()
