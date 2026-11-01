from django.urls import path

from . import views

urlpatterns = [
    path("", views.landing_page, name="landing_page"),
    path("report/", views.report_incident, name="report_incident"),
    path("report/<str:reference>/", views.report_confirmation, name="report_confirmation"),
    path("detection/", views.detection_lab, name="detection_lab"),
    path("detection/result/<int:pk>/", views.detection_result, name="detection_result"),
    path("history/", views.detection_history, name="detection_history"),
    path("management/login/", views.management_login, name="management_login"),
    path("management/logout/", views.management_logout, name="management_logout"),
    path("management/", views.management_dashboard, name="management_dashboard"),
    path("management/incidents/", views.review_queue, name="review_queue"),
    path("management/incidents/<int:pk>/", views.incident_detail, name="incident_detail"),
    path("management/incidents/<int:pk>/evidence/", views.download_incident_evidence, name="download_incident_evidence"),
    path("management/incidents/<int:pk>/export/", views.export_incident_report, name="export_incident_report"),
    path("management/model-status/", views.model_status, name="model_status"),

    path("message-detect/", views.message_detection, name="message_detection"),
    path("message-detect/result/<int:pk>/", views.message_result, name="message_result"),

    path("management/kb/messages/", views.kb_message_list, name="kb_message_list"),
    path("management/kb/messages/add/", views.kb_message_add, name="kb_message_add"),
    path("management/kb/messages/<int:pk>/edit/", views.kb_message_edit, name="kb_message_edit"),
    path("management/kb/messages/<int:pk>/toggle/", views.kb_message_toggle, name="kb_message_toggle"),
    path("management/kb/urls/", views.kb_url_list, name="kb_url_list"),
    path("management/kb/urls/add/", views.kb_url_add, name="kb_url_add"),
    path("management/kb/urls/<int:pk>/edit/", views.kb_url_edit, name="kb_url_edit"),
    path("management/kb/urls/<int:pk>/toggle/", views.kb_url_toggle, name="kb_url_toggle"),

    path("user/register/", views.user_register, name="user_register"),
    path("user/login/", views.user_login, name="user_login"),
    path("user/logout/", views.user_logout, name="user_logout"),
    path("user/dashboard/", views.user_dashboard, name="user_dashboard"),
    path("user/history/", views.user_history, name="user_history"),
    path("user/incidents/", views.user_incidents, name="user_incidents"),

    path("management/simulation/control/", views.simulation_control, name="simulation_control"),
    path("management/simulation/status/", views.simulation_status, name="simulation_status"),
    path("management/simulation/analyse/", views.simulation_analyse, name="simulation_analyse"),
]
