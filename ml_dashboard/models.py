from django.db import models

class Vulnerability(models.Model):
    cve_id = models.CharField(max_length=50, unique=True)
    title = models.CharField(max_length=500)
    cvss_score = models.FloatField(null=True, blank=True)
    base_severity = models.CharField(max_length=50)
    epss_score = models.FloatField(null=True, blank=True)
    vendor = models.CharField(max_length=200)
    published_date = models.DateTimeField()
    end_date = models.DateTimeField(null=True, blank=True)
    predicted_end_date = models.DateTimeField(null=True, blank=True)
    cluster_id = models.IntegerField(null=True, blank=True)
    is_critical = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.cve_id} - {self.title[:50]}"