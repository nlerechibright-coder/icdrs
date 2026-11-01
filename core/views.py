import csv
from pathlib import Path

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import FileResponse, Http404, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from .forms import DetectionInputForm, ManualIncidentForm, StatusUpdateForm
from .ml import FEATURES, build_demo_examples, determine_detection_result, get_model_status
from .models import DetectionEvent, Incident, IncidentUpdate, MessageKnowledgeBase, URLKnowledgeBase


def landing_page(request):
    return render(request, "core/home.html")


def _create_incident_for_detection(event, title="Potential suspicious network activity"):
    incident = Incident.objects.create(
        reference=Incident().generate_reference(),
        title=title,
        category="network_activity",
        severity=event.severity,
        status="new",
        description=(
            "A network activity analysis generated a suspicious classification. "
            "This record was created as an internal incident for follow-up review."
        ),
        reporter_name="ICDRS Detection Engine",
        source="detection",
        detection_event=event,
        review_notes="Auto-created from suspicious detection.",
    )
    return incident


def _record_detection(feature_values, source="manual", example_label="Selected network activity"):
    result = determine_detection_result(feature_values)
    event = DetectionEvent.objects.create(
        source=source,
        detection_mode=result.get("mode", "simulation"),
        predicted_label=result["label"],
        severity=result["severity"],
        confidence=result["confidence"],
        is_suspicious=result["label"] == "suspicious",
        explanation=result.get("explanation", ""),
        recommendation=result.get("recommendation", ""),
        feature_summary=feature_values,
    )
    warning = result.get("warning")
    if warning:
        event.explanation = (
            f"Simulation Mode is active because the trained model could not be used: {warning}\n\n"
            f"{event.explanation}"
        )
        event.save(update_fields=["explanation"])

    if event.is_suspicious:
        _create_incident_for_detection(event, title=example_label)

    return event


def detection_lab(request):
    examples = build_demo_examples()
    selected_example = request.GET.get("example")
    example_values = examples.get(selected_example) if selected_example in examples else None
    form = DetectionInputForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        feature_values = {field: form.cleaned_data[field] for field in FEATURES}
        example_name = request.POST.get("example_name", "")
        is_demo = example_name in examples
        source = "demo" if is_demo else "manual"
        event = _record_detection(
            feature_values,
            source=source,
            example_label=example_name.replace("_", " ").title() if is_demo else "Selected network activity",
        )
        return redirect("detection_result", pk=event.pk)

    if request.method == "GET" and example_values:
        form = DetectionInputForm(initial=example_values)

    return render(request, "core/detection_lab.html", {
        "form": form,
        "examples": examples,
        "selected_example": selected_example,
    })


def detection_result(request, pk):
    event = get_object_or_404(DetectionEvent, pk=pk)
    incident = event.incidents.first()
    return render(request, "core/detection_result.html", {"event": event, "incident": incident})


def detection_history(request):
    events = DetectionEvent.objects.all()[:20]
    return render(request, "core/detection_history.html", {"events": events})


def report_incident(request):
    form = ManualIncidentForm(request.POST or None, request.FILES or None)
    if request.method == "POST" and form.is_valid():
        incident = Incident.objects.create(
            reference=Incident().generate_reference(),
            title=f"Manual report: {form.cleaned_data['category'].replace('_', ' ').title()}",
            category=form.cleaned_data["category"],
            severity="medium",
            status="new",
            description=form.cleaned_data["description"],
            reporter_name=form.cleaned_data["reporter_name"],
            contact_info=form.cleaned_data.get("contact_info", ""),
            website_url=form.cleaned_data.get("website_url", ""),
            evidence=request.FILES.get("evidence"),
            source="manual",
        )
        if form.cleaned_data.get("occurred_at"):
            incident.description = f"{incident.description}\nApproximate incident time: {form.cleaned_data['occurred_at'].isoformat()}"
            incident.save(update_fields=["description"])
        return redirect("report_confirmation", reference=incident.reference)
    return render(request, "core/report_incident.html", {"form": form})


def report_confirmation(request, reference):
    incident = get_object_or_404(Incident, reference=reference)
    return render(request, "core/report_confirmation.html", {"incident": incident})


@login_required(login_url="management_login")
@user_passes_test(lambda user: user.is_staff, login_url="management_login")
def management_dashboard(request):
    total_detected = DetectionEvent.objects.count()
    suspicious = DetectionEvent.objects.filter(is_suspicious=True).count()
    total_incidents = Incident.objects.count()
    open_incidents = Incident.objects.filter(status__in=["new", "under_review", "escalated"]).count()
    high_severity = Incident.objects.filter(severity__in=["high", "critical"]).count()
    recent_incidents = Incident.objects.order_by("-created_at")[:5]
    recent_detections = DetectionEvent.objects.order_by("-created_at")[:5]
    from .models import MessageKnowledgeBase, URLKnowledgeBase
    kb_fraud_count = MessageKnowledgeBase.objects.filter(classification='fraudulent', is_active=True).count()
    kb_legit_count = MessageKnowledgeBase.objects.filter(classification='legitimate', is_active=True).count()
    kb_url_count = URLKnowledgeBase.objects.filter(is_active=True).count()
    network_event_count = DetectionEvent.objects.filter(detection_mode__in=["machine_learning", "simulation"]).count()
    message_event_count = DetectionEvent.objects.filter(detection_mode="knowledge_base").count()
    model_status = get_model_status()
    return render(request, "core/management_dashboard.html", {
        "total_detected": total_detected,
        "suspicious": suspicious,
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "high_severity": high_severity,
        "recent_incidents": recent_incidents,
        "recent_detections": recent_detections,
        "model_status": model_status,
        "kb_fraud_count": kb_fraud_count,
        "kb_legit_count": kb_legit_count,
        "kb_url_count": kb_url_count,
        "network_event_count": network_event_count,
        "message_event_count": message_event_count,
    })


@login_required(login_url="management_login")
@user_passes_test(lambda user: user.is_staff, login_url="management_login")
def review_queue(request):
    incidents = Incident.objects.all()
    category = request.GET.get("category")
    status = request.GET.get("status")
    severity = request.GET.get("severity")

    if category:
        incidents = incidents.filter(category=category)
    if status:
        incidents = incidents.filter(status=status)
    if severity:
        incidents = incidents.filter(severity=severity)

    return render(request, "core/review_queue.html", {
        "incidents": incidents,
        "filters": {"category": category, "status": status, "severity": severity},
        "incident_categories": Incident.CATEGORY_CHOICES,
        "incident_statuses": Incident.STATUS_CHOICES,
        "incident_severities": Incident.SEVERITY_CHOICES,
    })


@login_required(login_url="management_login")
@user_passes_test(lambda user: user.is_staff, login_url="management_login")
def incident_detail(request, pk):
    incident = get_object_or_404(Incident, pk=pk)
    form = StatusUpdateForm(request.POST or None, initial={"status": incident.status, "review_notes": incident.review_notes})

    if request.method == "POST" and form.is_valid():
        incident.status = form.cleaned_data["status"]
        review_notes = form.cleaned_data["review_notes"] or ""
        incident.review_notes = review_notes
        incident.save()
        if review_notes:
            IncidentUpdate.objects.create(incident=incident, note=review_notes, created_by=request.user)
        messages.success(request, "Incident status updated successfully.")
        return redirect("incident_detail", pk=incident.pk)

    return render(request, "core/incident_detail.html", {"incident": incident, "form": form})


@login_required(login_url="management_login")
@user_passes_test(lambda user: user.is_staff, login_url="management_login")
def model_status(request):
    return render(request, "core/model_status.html", {"model_status": get_model_status()})


@login_required(login_url="management_login")
@user_passes_test(lambda user: user.is_staff, login_url="management_login")
def download_incident_evidence(request, pk):
    incident = get_object_or_404(Incident, pk=pk)
    if not incident.evidence:
        raise Http404("This incident has no attached evidence.")
    try:
        evidence_file = incident.evidence.open("rb")
    except OSError as exc:
        raise Http404("The attached evidence file is unavailable.") from exc
    return FileResponse(
        evidence_file,
        as_attachment=True,
        filename=Path(incident.evidence.name).name,
    )


@login_required(login_url="management_login")
@user_passes_test(lambda user: user.is_staff, login_url="management_login")
def export_incident_report(request, pk):
    incident = get_object_or_404(Incident, pk=pk)
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="{incident.reference}.csv"'
    writer = csv.writer(response)
    writer.writerow(["reference", "title", "category", "status", "severity", "reporter_name", "contact_info", "created_at", "description", "review_notes"])
    writer.writerow([
        incident.reference,
        _csv_safe_value(incident.title),
        incident.category,
        incident.status,
        incident.severity,
        _csv_safe_value(incident.reporter_name),
        _csv_safe_value(incident.contact_info),
        incident.created_at.isoformat(),
        _csv_safe_value(incident.description),
        _csv_safe_value(incident.review_notes),
    ])
    return response


def _csv_safe_value(value):
    value = str(value or "")
    if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


def management_login(request):
    next_url = request.POST.get("next", "") or request.GET.get("next", "")
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")
        user = authenticate(request, username=username, password=password)
        if user is not None and user.is_active and user.is_staff:
            login(request, user)
            if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
                next_url = reverse("management_dashboard")
            return HttpResponseRedirect(next_url)
        messages.error(request, "Invalid username or password.")
    return render(request, "core/management_login.html", {"next_url": next_url})


@login_required(login_url="management_login")
@require_POST
def management_logout(request):
    logout(request)
    return redirect("landing_page")

from .forms import MessageDetectionForm
from .detection_engine import analyze_message

def message_detection(request):
    if request.method == 'POST':
        form = MessageDetectionForm(request.POST)
        if form.is_valid():
            text = form.cleaned_data['message_text']
            result = analyze_message(text)
            
            # Save to DetectionEvent
            event = DetectionEvent.objects.create(
                source="manual",
                detection_mode="knowledge_base",
                predicted_label=result["label"],
                severity=result["severity"],
                confidence=result["confidence"],
                is_suspicious=result["label"] in ["Fraudulent", "Suspicious"],
                explanation=result["explanation"],
                recommendation=result["recommendation"],
                feature_summary=result["feature_summary"],
                input_text=text,
                user=request.user if request.user.is_authenticated else None
            )
            
            # Auto-create incident if suspicious
            if event.is_suspicious:
                Incident.objects.create(
                    reference=Incident().generate_reference(),
                    title=f"Auto-detected: {result['label']} Message",
                    category="phishing" if "phishing" in result["explanation"].lower() else "fraud",
                    severity=event.severity,
                    status="new",
                    description=f"User submitted message flagged as {result['label']}.\n\nMessage: {text}\n\nExplanation: {result['explanation']}",
                    reporter_name="System Detection",
                    source="detection",
                    detection_event=event,
                    review_notes="Auto-created from suspicious message detection."
                )
            
            return redirect("message_result", pk=event.pk)
    else:
        form = MessageDetectionForm()
    
    return render(request, "core/message_detection.html", {"form": form})

def message_result(request, pk):
    event = get_object_or_404(DetectionEvent, pk=pk)
    incident = event.incidents.first()
    return render(request, "core/message_result.html", {"event": event, "incident": incident})

# --- Knowledge Base Management Views ---
@login_required(login_url="management_login")
@user_passes_test(lambda user: user.is_staff, login_url="management_login")
def kb_message_list(request):
    messages = MessageKnowledgeBase.objects.all().order_by('-created_at')
    return render(request, "core/kb_message_list.html", {"messages": messages})

@login_required(login_url="management_login")
@user_passes_test(lambda user: user.is_staff, login_url="management_login")
def kb_message_add(request):
    if request.method == "POST":
        MessageKnowledgeBase.objects.create(
            content=request.POST.get("content", "").strip(),
            classification=request.POST.get("classification"),
            fraud_category=request.POST.get("fraud_category", "").strip(),
            keywords=request.POST.get("keywords", "").strip(),
            source_description=request.POST.get("source_description", "").strip(),
            is_active=request.POST.get("is_active") == "on",
            added_by=request.user
        )
        from django.contrib import messages
        messages.success(request, "Message added to knowledge base.")
        return redirect("kb_message_list")
    return render(request, "core/kb_message_form.html", {"mode": "add"})

@login_required(login_url="management_login")
@user_passes_test(lambda user: user.is_staff, login_url="management_login")
def kb_message_edit(request, pk):
    obj = get_object_or_404(MessageKnowledgeBase, pk=pk)
    if request.method == "POST":
        obj.content = request.POST.get("content", "").strip()
        obj.classification = request.POST.get("classification")
        obj.fraud_category = request.POST.get("fraud_category", "").strip()
        obj.keywords = request.POST.get("keywords", "").strip()
        obj.source_description = request.POST.get("source_description", "").strip()
        obj.is_active = request.POST.get("is_active") == "on"
        obj.save()
        from django.contrib import messages
        messages.success(request, "Message updated.")
        return redirect("kb_message_list")
    return render(request, "core/kb_message_form.html", {"mode": "edit", "obj": obj})

@login_required(login_url="management_login")
@user_passes_test(lambda user: user.is_staff, login_url="management_login")
def kb_message_toggle(request, pk):
    obj = get_object_or_404(MessageKnowledgeBase, pk=pk)
    obj.is_active = not obj.is_active
    obj.save()
    from django.contrib import messages
    status = "activated" if obj.is_active else "deactivated"
    messages.success(request, f"Message {status}.")
    return redirect("kb_message_list")

@login_required(login_url="management_login")
@user_passes_test(lambda user: user.is_staff, login_url="management_login")
def kb_url_list(request):
    urls = URLKnowledgeBase.objects.all().order_by('-created_at')
    return render(request, "core/kb_url_list.html", {"urls": urls})

@login_required(login_url="management_login")
@user_passes_test(lambda user: user.is_staff, login_url="management_login")
def kb_url_add(request):
    if request.method == "POST":
        URLKnowledgeBase.objects.create(
            url=request.POST.get("url", "").strip(),
            classification=request.POST.get("classification"),
            description=request.POST.get("description", "").strip(),
            is_active=request.POST.get("is_active") == "on"
        )
        from django.contrib import messages
        messages.success(request, "URL added to knowledge base.")
        return redirect("kb_url_list")
    return render(request, "core/kb_url_form.html", {"mode": "add"})

@login_required(login_url="management_login")
@user_passes_test(lambda user: user.is_staff, login_url="management_login")
def kb_url_edit(request, pk):
    obj = get_object_or_404(URLKnowledgeBase, pk=pk)
    if request.method == "POST":
        obj.url = request.POST.get("url", "").strip()
        obj.classification = request.POST.get("classification")
        obj.description = request.POST.get("description", "").strip()
        obj.is_active = request.POST.get("is_active") == "on"
        obj.save()
        from django.contrib import messages
        messages.success(request, "URL updated.")
        return redirect("kb_url_list")
    return render(request, "core/kb_url_form.html", {"mode": "edit", "obj": obj})

@login_required(login_url="management_login")
@user_passes_test(lambda user: user.is_staff, login_url="management_login")
def kb_url_toggle(request, pk):
    obj = get_object_or_404(URLKnowledgeBase, pk=pk)
    obj.is_active = not obj.is_active
    obj.save()
    from django.contrib import messages
    status = "activated" if obj.is_active else "deactivated"
    messages.success(request, f"URL {status}.")
    return redirect("kb_url_list")

from django.contrib.auth import login as auth_login, logout as auth_logout
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm

def user_register(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            auth_login(request, user)
            return redirect('user_dashboard')
    else:
        form = UserCreationForm()
    return render(request, 'core/user_register.html', {'form': form})

def user_login(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            auth_login(request, form.get_user())
            return redirect('user_dashboard')
    else:
        form = AuthenticationForm()
    return render(request, 'core/user_login.html', {'form': form})

@login_required(login_url='user_login')
def user_logout(request):
    auth_logout(request)
    return redirect('user_login')

@login_required(login_url='user_login')
def user_dashboard(request):
    event_count = DetectionEvent.objects.filter(user=request.user).count()
    incident_count = Incident.objects.filter(user=request.user).count()
    recent_events = DetectionEvent.objects.filter(user=request.user).order_by('-created_at')[:5]
    return render(request, 'core/user_dashboard.html', {
        'event_count': event_count,
        'incident_count': incident_count,
        'recent_events': recent_events
    })

@login_required(login_url='user_login')
def user_history(request):
    events = DetectionEvent.objects.filter(user=request.user).order_by('-created_at')
    return render(request, 'core/user_history.html', {'events': events})

@login_required(login_url='user_login')
def user_incidents(request):
    incidents = Incident.objects.filter(user=request.user).order_by('-created_at')
    return render(request, 'core/user_incidents.html', {'incidents': incidents})
