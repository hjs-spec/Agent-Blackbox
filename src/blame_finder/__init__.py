"""
Agent Blame-Finder - Cryptographic blackbox for multi-agent systems.

Find out which agent messed up in 3 seconds.
"""

__version__ = "0.1.0"
__author__ = "HJS Foundation"
__license__ = "MIT"

from .core import BlameFinder, JEPReceipt, Verdict
from .cli import main

__all__ = ["BlameFinder", "JEPReceipt", "Verdict", "main"]
