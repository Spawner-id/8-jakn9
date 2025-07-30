#!/usr/bin/env python3
"""
Main entry point for the Telegram bot.
This file runs the bot from botV2.py
"""

import sys
import os

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run the bot
from botV2 import main

if __name__ == "__main__":
    main()
