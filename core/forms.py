from django import forms
from django.core.exceptions import ValidationError


class DetectionInputForm(forms.Form):
    duration_seconds = forms.FloatField(
        min_value=0,
        label="Connection duration (seconds)",
        widget=forms.NumberInput(attrs={"class": "w-full rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-3 text-slate-100 focus:border-cyan-500 focus:outline-none"}),
    )
    bytes_src_to_dst = forms.FloatField(
        min_value=0,
        label="Source to destination bytes",
        widget=forms.NumberInput(attrs={"class": "w-full rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-3 text-slate-100 focus:border-cyan-500 focus:outline-none"}),
    )
    bytes_dst_to_src = forms.FloatField(
        min_value=0,
        label="Destination to source bytes",
        widget=forms.NumberInput(attrs={"class": "w-full rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-3 text-slate-100 focus:border-cyan-500 focus:outline-none"}),
    )
    failed_connections = forms.IntegerField(
        min_value=0,
        label="Failed connections",
        widget=forms.NumberInput(attrs={"class": "w-full rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-3 text-slate-100 focus:border-cyan-500 focus:outline-none"}),
    )
    connection_frequency = forms.IntegerField(
        min_value=0,
        label="Connection frequency",
        widget=forms.NumberInput(attrs={"class": "w-full rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-3 text-slate-100 focus:border-cyan-500 focus:outline-none"}),
    )
    service_anomaly_score = forms.FloatField(
        min_value=0,
        max_value=1,
        label="Service anomaly score",
        widget=forms.NumberInput(attrs={"class": "w-full rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-3 text-slate-100 focus:border-cyan-500 focus:outline-none"}),
    )


class ManualIncidentForm(forms.Form):
    reporter_name = forms.CharField(
        max_length=150,
        label="Reporter name",
        widget=forms.TextInput(attrs={"class": "w-full rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-3 text-slate-100 focus:border-cyan-500 focus:outline-none"}),
    )
    contact_info = forms.CharField(
        max_length=200,
        required=False,
        label="Contact information",
        widget=forms.TextInput(attrs={"class": "w-full rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-3 text-slate-100 focus:border-cyan-500 focus:outline-none"}),
    )
    category = forms.ChoiceField(
        choices=[
            ("phishing", "Phishing"),
            ("fraud", "Online fraud"),
            ("account_compromise", "Account compromise"),
            ("network_activity", "Suspicious network activity"),
            ("malware", "Malware suspicion"),
            ("other", "Other cybercrime"),
        ],
        label="Incident category",
        widget=forms.Select(attrs={"class": "w-full rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-3 text-slate-100 focus:border-cyan-500 focus:outline-none"}),
    )
    description = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 5, "class": "w-full rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-3 text-slate-100 focus:border-cyan-500 focus:outline-none"}),
        label="Incident description",
    )
    occurred_at = forms.DateTimeField(
        required=False,
        label="Approximate date and time",
        widget=forms.DateTimeInput(attrs={"class": "w-full rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-3 text-slate-100 focus:border-cyan-500 focus:outline-none", "type": "datetime-local"}),
    )
    website_url = forms.URLField(
        required=False,
        label="Relevant website or URL",
        widget=forms.URLInput(attrs={"class": "w-full rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-3 text-slate-100 focus:border-cyan-500 focus:outline-none"}),
    )
    evidence = forms.FileField(
        required=False,
        label="Evidence attachment",
        widget=forms.ClearableFileInput(attrs={"class": "w-full rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-3 text-slate-100 file:mr-4 file:rounded-full file:border-0 file:bg-cyan-500 file:px-4 file:py-2 file:text-sm file:font-semibold file:text-slate-950"}),
    )

    def clean_evidence(self):
        uploaded_file = self.cleaned_data.get("evidence")
        if not uploaded_file:
            return uploaded_file
        if uploaded_file.size > 5 * 1024 * 1024:
            raise ValidationError("Evidence attachment must be 5 MB or smaller.")
        allowed = {".pdf", ".png", ".jpg", ".jpeg", ".txt", ".csv"}
        extension = uploaded_file.name.lower()
        allowed_name = any(extension.endswith(ext) for ext in allowed)
        if not allowed_name:
            raise ValidationError("Unsupported document type. Please upload a PDF, image, text, or CSV file.")
        return uploaded_file


class StatusUpdateForm(forms.Form):
    status = forms.ChoiceField(
        choices=[
            ("new", "New"),
            ("under_review", "Under Review"),
            ("escalated", "Escalated"),
            ("resolved", "Resolved"),
            ("closed", "Closed"),
        ],
        widget=forms.Select(attrs={"class": "w-full rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-3 text-slate-100 focus:border-cyan-500 focus:outline-none"}),
    )
    review_notes = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 4, "class": "w-full rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-3 text-slate-100 focus:border-cyan-500 focus:outline-none"}),
        required=False,
    )

class MessageDetectionForm(forms.Form):
    message_text = forms.CharField(
        label="Paste Message or Email Text",
        widget=forms.Textarea(attrs={
            "rows": 6, 
            "class": "w-full rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-3 text-slate-100 focus:border-cyan-500 focus:outline-none",
            "placeholder": "e.g., Dear Customer, your account has been suspended. Click here to verify..."
        }),
        help_text="Paste the full text of the SMS, email, or message you want to analyze."
    )
