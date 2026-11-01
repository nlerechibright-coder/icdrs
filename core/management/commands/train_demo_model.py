from django.core.management.base import BaseCommand, CommandError

from core.ml import train_demo_model


class Command(BaseCommand):
    help = "Train the demo Random Forest classifier for the ICDRS network detection prototype."

    def handle(self, *args, **options):
        try:
            metrics = train_demo_model()
        except (FileNotFoundError, ValueError) as exc:
            raise CommandError(str(exc)) from exc

        self.stdout.write(self.style.SUCCESS("Demo model trained successfully."))
        self.stdout.write(f"Accuracy: {metrics['accuracy']:.4f}")
        self.stdout.write(f"Precision: {metrics['precision']:.4f}")
        self.stdout.write(f"Recall: {metrics['recall']:.4f}")
        self.stdout.write(f"F1-score: {metrics['f1_score']:.4f}")
