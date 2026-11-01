from getpass import getpass

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Create a local admin account for the ICDRS management dashboard."

    def add_arguments(self, parser):
        parser.add_argument("--username", default="admin")
        parser.add_argument("--email", default="admin@icdrs.local")

    def handle(self, *args, **options):
        User = get_user_model()
        username = options["username"]
        email = options["email"]

        if User.objects.filter(username=username).exists():
            self.stdout.write(self.style.WARNING(f"User '{username}' already exists."))
            return

        password = getpass("Password: ")
        password_confirmation = getpass("Confirm password: ")
        if password != password_confirmation:
            raise CommandError("The passwords did not match.")

        user = User(username=username, email=email, is_staff=True, is_superuser=True)
        try:
            validate_password(password, user=user)
        except ValidationError as exc:
            raise CommandError("; ".join(exc.messages)) from exc
        user.set_password(password)
        user.save()
        self.stdout.write(self.style.SUCCESS(f"Created administrator account for {user.username}."))
