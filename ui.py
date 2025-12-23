from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.console import Console

def get_progress_bar(console: Console, description="Processing...", total=None):
    """
    Returns a configured Progress instance with a bar, spinner, and percentage.
    """
    return Progress(
        SpinnerColumn(),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console
    )
