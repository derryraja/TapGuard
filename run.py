#!/usr/bin/env python3
"""TapGuard - entry point.

Launches the GUI. All detection logic lives in the ``tapguard``
package so it can be driven from a GUI, a CLI, or tests.
"""
from tapguard.gui.app import main

if __name__ == "__main__":
    main()
