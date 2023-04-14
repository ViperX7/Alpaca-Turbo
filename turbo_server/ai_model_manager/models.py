from django.db import models



class AIModelSettings(models.Model):
    ai_model = models.ForeignKey("AIModel", on_delete=models.CASCADE)
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
    source = models.URLField()
    model_format = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    path = models.FilePathField()
    settings = models.ForeignKey("AIModelSettings", on_delete=models.CASCADE)


