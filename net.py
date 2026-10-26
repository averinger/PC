#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.expanduser("~"))
from nettool.ui import run
if __name__ == '__main__':
    try: run()
    except KeyboardInterrupt:
        print("\n\033[93mВыход.\033[0m\n")
