
from django.core.management.commands.runserver import Command as RunserverCommand
from django.core.management import call_command


class Command(RunserverCommand):
    def handle(self, *args, **options):
        # Run the parse_logs command before starting the server
        print("Running parse_logs command...")  # Debug statement
        call_command('parse_logs')
        super().handle(*args, **options)