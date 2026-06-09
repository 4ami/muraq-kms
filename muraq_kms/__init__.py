from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("muraq-kms")
except PackageNotFoundError:
    __version__ = "0.0.0-dev"

__all__ = ["__version__"]