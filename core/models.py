import uuid

from django.conf import settings
from django.db import models


class DetectionEvent(models.Model):
    MODE_CHOICES = [
        ("machine_learning", "Machine Learning"),
        ("simulation", "Simulation"),
        ("knowledge_base", "Knowledge Base"),
    ]
    SOURCE_CHOICES = [
        ("manual", "Manual input"),
        ("demo", "Built-in example"),
        ("uploaded", "CSV upload"),
        ("system", "System detection"),
    ]

    input_text = models.TextField(blank=True, default="")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="detection_events")
    created_at = models.DateTimeField(auto_now_add=True)
    source = models.CharField(max_length=20, choices=SOURCE_CHOICES, default="manual")
    detection_mode = models.CharField(max_length=24, choices=MODE_CHOICES, default="machine_learning")
    predicted_label = models.CharField(max_length=20)
    severity = models.CharField(max_length=20, default="low")
    confidence = models.FloatField(default=0.0)
    is_suspicious = models.BooleanField(default=False)
    explanation = models.TextField(blank=True)
    recommendation = models.TextField(blank=True)
    feature_summary = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.predicted_label} ({self.created_at:%Y-%m-%d %H:%M})"


class Incident(models.Model):
    CATEGORY_CHOICES = [
        ("phishing", "Phishing"),
        ("fraud", "Online fraud"),
        ("account_compromise", "Account compromise"),
        ("network_activity", "Suspicious network activity"),
        ("malware", "Malware suspicion"),
        ("other", "Other cybercrime"),
    ]
    SEVERITY_CHOICES = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]
    STATUS_CHOICES = [
        ("new", "New"),
        ("under_review", "Under Review"),
        ("escalated", "Escalated"),
        ("resolved", "Resolved"),
        ("closed", "Closed"),
    ]

    reference = models.CharField(max_length=30, unique=True)
    title = models.CharField(max_length=200)
    category = models.CharField(max_length=30, choices=CATEGORY_CHOICES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default="medium")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="new")
    description = models.TextField()
    reporter_name = models.CharField(max_length=150)
    contact_info = models.CharField(max_length=250, blank=True)
    website_url = models.URLField(blank=True)
    evidence = models.FileField(upload_to="evidence/%Y/%m/%d", blank=True)
    source = models.CharField(max_length=30, default="manual")
    detection_event = models.ForeignKey("DetectionEvent", on_delete=models.SET_NULL, null=True, blank=True, related_name="incidents")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="incidents")
    review_notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.reference} - {self.title}"

    def generate_reference(self):
        return f"ICDR-{uuid.uuid4().hex[:8].upper()}"


class IncidentUpdate(models.Model):
    incident = models.ForeignKey(Incident, related_name="history", on_delete=models.CASCADE)
    note = models.TextField()
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.incident.reference} - {self.created_at:%Y-%m-%d %H:%M}"


class MessageKnowledgeBase(models.Model):
    CLASSIFICATION_CHOICES = [
        ("fraudulent", "Fraudulent"),
        ("legitimate", "Legitimate"),
    ]
    
    content = models.TextField(help_text="The exact text of the message.")
    classification = models.CharField(max_length=20, choices=CLASSIFICATION_CHOICES)
    fraud_category = models.CharField(max_length=50, blank=True, help_text="e.g., Phishing, Advance-fee")
    keywords = models.TextField(blank=True, help_text="Comma-separated high-risk phrases.")
    source_description = models.CharField(max_length=200, blank=True)
    is_active = models.BooleanField(default=True)
    added_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.classification.title()} - {self.content[:50]}"


class URLKnowledgeBase(models.Model):
    CLASSIFICATION_CHOICES = [
        ("phishing", "Phishing"),
        ("legitimate", "Legitimate"),
    ]
    
    url = models.URLField(max_length=500)
    domain = models.CharField(max_length=255, blank=True)
    classification = models.CharField(max_length=20, choices=CLASSIFICATION_CHOICES)
    description = models.CharField(max_length=200, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def save(self, *args, **kwargs):
        if not self.domain:
            from urllib.parse import urlparse
            self.domain = urlparse(self.url).netloc.replace('www.', '')
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.classification.title()} - {self.domain}"
