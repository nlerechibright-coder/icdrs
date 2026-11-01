import json
import tempfile
from unittest.mock import patch
from pathlib import Path

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from core.ml import (
    FEATURES,
    MODEL_PATH,
    build_demo_examples,
    determine_detection_result,
    get_model_status,
    predict_with_model,
)
from core.models import DetectionEvent, Incident, IncidentUpdate


class ICDRSTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin_user = get_user_model().objects.create_user(
            username="admin",
            password="SecureDemoPassword-2026",
            is_staff=True,
            is_superuser=True,
        )

    def create_incident(self, **overrides):
        defaults = {
            "reference": "ICDR-TEST0001",
            "title": "Manual report: Fraud",
            "category": "fraud",
            "description": "A test report for the review flow.",
            "reporter_name": "Test Reporter",
            "source": "manual",
        }
        defaults.update(overrides)
        return Incident.objects.create(**defaults)

    def post_detection(self, values, example_name=None):
        data = dict(values)
        if example_name:
            data["example_name"] = example_name
        return self.client.post(reverse("detection_lab"), data)

    def test_public_landing_and_detection_lab_render(self):
        self.assertEqual(self.client.get(reverse("landing_page")).status_code, 200)
        response = self.client.get(reverse("detection_lab"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Analyse Activity")

    def test_saved_model_schema_and_demo_predictions(self):
        if not MODEL_PATH.exists():
            self.skipTest("Train the demo model to run the saved-model integration check.")

        self.assertTrue(get_model_status()["available"])
        examples = build_demo_examples()
        suspicious = predict_with_model(examples["repeated_probe_scan"])
        normal = predict_with_model(examples["baseline_guest_traffic"])
        self.assertEqual(suspicious["label"], "suspicious")
        self.assertIn("rather than proof", suspicious["explanation"])
        self.assertEqual(normal["label"], "normal")
        self.assertEqual(len(FEATURES), 6)

    def test_builtin_suspicious_scenario_creates_incident(self):
        response = self.post_detection(
            build_demo_examples()["repeated_probe_scan"],
            example_name="repeated_probe_scan",
        )
        self.assertEqual(response.status_code, 302)
        event = DetectionEvent.objects.get()
        incident = Incident.objects.get()
        self.assertEqual(event.source, "demo")
        self.assertEqual(event.detection_mode, "machine_learning")
        self.assertEqual(event.predicted_label, "suspicious")
        self.assertIn("suspicious", event.explanation.lower())
        self.assertEqual(incident.detection_event, event)
        self.assertEqual(incident.source, "detection")
        self.assertEqual(incident.status, "new")

    def test_normal_scenario_does_not_create_incident(self):
        response = self.post_detection(build_demo_examples()["baseline_guest_traffic"])
        self.assertEqual(response.status_code, 302)
        event = DetectionEvent.objects.get()
        self.assertEqual(event.predicted_label, "normal")
        self.assertFalse(event.is_suspicious)
        self.assertFalse(Incident.objects.exists())

    @patch(
        "core.views.determine_detection_result",
        return_value={
            "mode": "simulation",
            "label": "normal",
            "severity": "low",
            "confidence": 0.62,
            "explanation": "Simulated result.",
            "recommendation": "Monitor.",
            "warning": "Corrupt model artifact.",
        },
    )
    def test_simulation_fallback_reason_is_persisted_and_displayed(self, _mock_result):
        response = self.post_detection(build_demo_examples()["baseline_guest_traffic"])
        self.assertEqual(response.status_code, 302)
        event = DetectionEvent.objects.get()
        self.assertEqual(event.detection_mode, "simulation")
        self.assertIn("Corrupt model artifact", event.explanation)
        result = self.client.get(response.url)
        self.assertEqual(result.status_code, 200)
        self.assertContains(result, "Simulation Mode")
        self.assertContains(result, "Corrupt model artifact")

    def test_missing_and_corrupt_model_artifacts_report_simulation_mode(self):
        examples = build_demo_examples()
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = Path(temp_dir) / "missing.joblib"
            metadata_path = Path(temp_dir) / "metadata.json"
            with (
                patch("core.ml.MODEL_PATH", model_path),
                patch("core.ml.METADATA_PATH", metadata_path),
            ):
                missing_result = determine_detection_result(examples["baseline_guest_traffic"])
                self.assertEqual(missing_result["mode"], "simulation")
                self.assertIn("train_demo_model", missing_result["warning"])

                model_path.write_text("invalid model bytes", encoding="utf-8")
                metadata_path.write_text(json.dumps({"feature_names": FEATURES}), encoding="utf-8")
                corrupt_status = get_model_status()
                self.assertFalse(corrupt_status["available"])
                self.assertEqual(corrupt_status["mode"], "simulation")
                self.assertIn("could not be validated", corrupt_status["error"])

    def test_invalid_detection_input_is_rejected(self):
        values = build_demo_examples()["baseline_guest_traffic"]
        values["duration_seconds"] = -1
        response = self.post_detection(values)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Ensure this value is greater than or equal to 0")
        self.assertFalse(DetectionEvent.objects.exists())

    def test_manual_report_validates_and_persists(self):
        response = self.client.post(reverse("report_incident"), {
            "reporter_name": "Alice Example",
            "category": "fraud",
            "description": "Received a fake investment offer.",
            "contact_info": "alice@example.com",
            "website_url": "https://example.com",
        })
        self.assertEqual(response.status_code, 302)
        incident = Incident.objects.get()
        self.assertTrue(incident.reference.startswith("ICDR-"))
        self.assertEqual(incident.source, "manual")
        self.assertEqual(
            self.client.get(response.url).status_code,
            200,
        )

    def test_manual_report_rejects_invalid_category_and_attachment(self):
        invalid_category = self.client.post(reverse("report_incident"), {
            "reporter_name": "Alice Example",
            "category": "invalid",
            "description": "Invalid category.",
        })
        self.assertEqual(invalid_category.status_code, 200)
        self.assertFalse(Incident.objects.exists())

        invalid_file = SimpleUploadedFile("payload.exe", b"not executable")
        response = self.client.post(reverse("report_incident"), {
            "reporter_name": "Alice Example",
            "category": "other",
            "description": "Attachment validation.",
            "evidence": invalid_file,
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Unsupported document type")
        self.assertFalse(Incident.objects.exists())

    def test_public_report_post_requires_csrf_token(self):
        client = Client(enforce_csrf_checks=True)
        client.get(reverse("report_incident"))
        response = client.post(reverse("report_incident"), {
            "reporter_name": "Alice Example",
            "category": "fraud",
            "description": "CSRF check.",
        })
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Incident.objects.exists())

    def test_management_pages_and_actions_require_staff(self):
        incident = self.create_incident()
        for url in (
            reverse("management_dashboard"),
            reverse("review_queue"),
            reverse("incident_detail", args=[incident.pk]),
            reverse("export_incident_report", args=[incident.pk]),
            reverse("model_status"),
        ):
            response = self.client.get(url)
            self.assertEqual(response.status_code, 302)
            self.assertIn(reverse("management_login"), response.url)

        response = self.client.post(
            reverse("incident_detail", args=[incident.pk]),
            {"status": "closed", "review_notes": "unauthorized"},
        )
        self.assertEqual(response.status_code, 302)
        incident.refresh_from_db()
        self.assertEqual(incident.status, "new")

    def test_non_staff_user_cannot_sign_in_to_management(self):
        get_user_model().objects.create_user(
            username="ordinary",
            password="OrdinaryPass-2026",
        )
        response = self.client.post(reverse("management_login"), {
            "username": "ordinary",
            "password": "OrdinaryPass-2026",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse("_auth_user_id" in self.client.session)

    def test_staff_user_can_review_and_update_incident(self):
        incident = self.create_incident()
        self.client.force_login(self.admin_user)
        self.assertEqual(self.client.get(reverse("management_dashboard")).status_code, 200)
        self.assertEqual(self.client.get(reverse("review_queue")).status_code, 200)

        response = self.client.post(
            reverse("incident_detail", args=[incident.pk]),
            {"status": "under_review", "review_notes": "Reviewed supporting information."},
        )
        self.assertEqual(response.status_code, 302)
        incident.refresh_from_db()
        self.assertEqual(incident.status, "under_review")
        self.assertEqual(incident.review_notes, "Reviewed supporting information.")
        self.assertTrue(IncidentUpdate.objects.filter(incident=incident).exists())

    def test_staff_can_view_history_and_model_status(self):
        DetectionEvent.objects.create(
            source="demo",
            detection_mode="machine_learning",
            predicted_label="normal",
            severity="low",
            confidence=0.8,
            is_suspicious=False,
        )
        self.client.force_login(self.admin_user)
        history = self.client.get(reverse("detection_history"))
        self.assertEqual(history.status_code, 200)
        self.assertContains(history, "Normal")

        model_status = self.client.get(reverse("model_status"))
        self.assertEqual(model_status.status_code, 200)
        if get_model_status()["metrics"]:
            self.assertContains(model_status, "not estimates of real-world cybercrime detection accuracy")

    def test_incident_csv_export_is_authorized_and_formula_safe(self):
        incident = self.create_incident(
            title="=HYPERLINK(\"https://example.com\")",
            description="+SUM(1,1)",
        )
        self.assertEqual(
            self.client.get(reverse("export_incident_report", args=[incident.pk])).status_code,
            302,
        )

        self.client.force_login(self.admin_user)
        response = self.client.get(reverse("export_incident_report", args=[incident.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/csv")
        body = response.content.decode("utf-8")
        self.assertIn("'=HYPERLINK", body)
        self.assertIn("'+SUM(1,1)", body)
        self.assertIn(incident.reference, body)

    def test_missing_records_return_404_and_logout_requires_post(self):
        self.assertEqual(self.client.get(reverse("detection_result", args=[9999])).status_code, 404)
        self.assertEqual(self.client.get(reverse("report_confirmation", args=["ICDR-MISSING"])).status_code, 404)
        self.assertEqual(self.client.get(reverse("incident_detail", args=[9999])).status_code, 302)

        self.client.force_login(self.admin_user)
        self.assertEqual(self.client.get(reverse("management_logout")).status_code, 405)
        response = self.client.post(reverse("management_logout"))
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_authorized_missing_incident_returns_404(self):
        self.client.force_login(self.admin_user)
        self.assertEqual(self.client.get(reverse("incident_detail", args=[9999])).status_code, 404)
        self.assertEqual(self.client.get(reverse("export_incident_report", args=[9999])).status_code, 404)

    def test_evidence_download_requires_staff_and_serves_as_attachment(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with override_settings(MEDIA_ROOT=temp_dir):
                incident = self.create_incident()
                incident.evidence.save(
                    "evidence.txt",
                    SimpleUploadedFile("evidence.txt", b"private evidence"),
                    save=True,
                )
                url = reverse("download_incident_evidence", args=[incident.pk])

                anonymous_response = self.client.get(url)
                self.assertEqual(anonymous_response.status_code, 302)

                self.client.force_login(self.admin_user)
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)
                self.assertIn("attachment", response["Content-Disposition"])
                self.assertEqual(b"".join(response.streaming_content), b"private evidence")
                response.close()

                public_media_path = incident.evidence.url
                self.assertEqual(self.client.get(public_media_path).status_code, 404)

    def test_login_rejects_external_redirect_target(self):
        response = self.client.post(reverse("management_login"), {
            "username": "admin",
            "password": "SecureDemoPassword-2026",
            "next": "https://attacker.example/",
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("management_dashboard"))

    def test_login_preserves_safe_redirect_target(self):
        response = self.client.post(reverse("management_login") + "?next=/management/incidents/", {
            "username": "admin",
            "password": "SecureDemoPassword-2026",
            "next": "/management/incidents/",
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/management/incidents/")
