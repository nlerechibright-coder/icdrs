from django.db import models
from django.conf import settings
import uuid

class MessageKnowledgeBase(models.Model):
    content = models.TextField()
    classification = models.CharField(max_length=20)
    fraud_category = models.CharField(max_length=100, blank=True, null=True)
    keywords = models.TextField(blank=True, null=True)
    source_description = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    added_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.classification} - {self.content[:50]}"

class URLKnowledgeBase(models.Model):
    url = models.URLField(unique=True)
    classification = models.CharField(max_length=20)
    description = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    @property
    def domain(self):
        from urllib.parse import urlparse
        return urlparse(self.url).netloc.replace('www.', '').lower()

    def __str__(self):
        return f"{self.classification} - {self.url}"

class DetectionEvent(models.Model):
    SOURCE_CHOICES = [('manual', 'Manual'), ('demo', 'Demo'), ('simulation', 'Simulation'), ('detection', 'Detection')]
    source = models.CharField(max_length=20, choices=SOURCE_CHOICES)
    detection_mode = models.CharField(max_length=50)
    predicted_label = models.CharField(max_length=50)
    severity = models.CharField(max_length=20)
    confidence = models.FloatField()
    is_suspicious = models.BooleanField(default=False)
    explanation = models.TextField(blank=True, null=True)
    recommendation = models.TextField(blank=True, null=True)
    feature_summary = models.JSONField(default=dict)
    input_text = models.TextField(blank=True, null=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.predicted_label} - {self.created_at}"

class Incident(models.Model):
    CATEGORY_CHOICES = [('phishing', 'Phishing'), ('fraud', 'Fraud'), ('network_activity', 'Network Activity'), ('other', 'Other')]
    STATUS_CHOICES = [('new', 'New'), ('under_review', 'Under Review'), ('escalated', 'Escalated'), ('resolved', 'Resolved'), ('closed', 'Closed')]
    SEVERITY_CHOICES = [('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')]

    reference = models.CharField(max_length=50, unique=True)
    title = models.CharField(max_length=200)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
    description = models.TextField()
    reporter_name = models.CharField(max_length=150)
    contact_info = models.CharField(max_length=200, blank=True, null=True)
    website_url = models.URLField(blank=True, null=True)
    evidence = models.FileField(upload_to='incident_evidence/', blank=True, null=True)
    source = models.CharField(max_length=20, choices=[('manual', 'Manual'), ('detection', 'Detection')])
    detection_event = models.OneToOneField(DetectionEvent, on_delete=models.SET_NULL, null=True, blank=True, related_name='incidents')
    review_notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)

    def generate_reference(self):
        return f"INC-{uuid.uuid4().hex[:8].upper()}"

    def __str__(self):
        return self.reference

class IncidentUpdate(models.Model):
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name='updates')
    note = models.TextField()
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Update for {self.incident.reference}"

class IncidentResponse(models.Model):
    ACTION_CHOICES = [
        ('INVESTIGATED', 'Investigated'), ('BLOCKED', 'Blocked'), 
        ('FALSE_POSITIVE', 'False Positive'), ('RESOLVED', 'Resolved'), ('UNBLOCKED', 'Unblocked')
    ]
    incident = models.ForeignKey('DetectionEvent', on_delete=models.CASCADE, related_name='responses')
    administrator = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    reason = models.TextField(blank=True, null=True)
    source_device = models.CharField(max_length=100, blank=True, null=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']

class NetworkBlocklist(models.Model):
    source_device = models.CharField(max_length=100)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    reason = models.TextField(blank=True, null=True)
    blocked_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='blocked_sources')
    blocked_at = models.DateTimeField(auto_now_add=True)
    unblocked_at = models.DateTimeField(null=True, blank=True)
    unblocked_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='unblocked_sources', blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        unique_together = ['source_device', 'is_active']
        ordering = ['-blocked_at']