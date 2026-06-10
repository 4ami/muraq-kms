import typer
from typing import Optional
from pathlib import Path

from muraq_kms.storage.config import StorageConfig
from muraq_kms.cli.shell import MKMSShell

app = typer.Typer(help="Muraq Key Management Subsystem (MKMS) CLI Engine Console.")

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    data_dir: Optional[Path] = typer.Option(
        None, 
        "--data-dir", "-d", 
        envvar="MKMS_DATA_DIR", 
        help="Custom root workspace path configuration."
    )
):
    """
    Launches the interactive cryptographic engine console environment if no subcommand is fed.
    """
    if ctx.invoked_subcommand is None:
        config = StorageConfig(base_dir=data_dir) if data_dir else StorageConfig.from_env()
        
        shell = MKMSShell(config=config)
        shell.cmdloop()

if __name__ == "__main__":
    app()