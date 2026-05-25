from PyQt5.QtCore import QThread
import subprocess
import sys

class NIDSThread(QThread):
    def __init__(self):
        super().__init__()
        self.process = None

    def run(self):
        # Run core NIDS script
        self.process = subprocess.Popen(
            [sys.executable, "-m", "nids_main"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        self.process.wait()

    def stop(self):
        if self.process:
            self.process.terminate()