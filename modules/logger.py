from datetime import datetime
import os

class Logger:
    def __init__(self, filepath):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        self.file = open(filepath, "a")
        self.file.write(f"\n{'='*60}\n")
        self.file.write(f"  NetSentry session started: {datetime.now()}\n")
        self.file.write(f"{'='*60}\n\n")
        self.file.flush()

    def log(self, alert):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = (f"[{ts}] [{alert['severity']}] {alert['type']} "
                f"| src: {alert['src_ip']} | {alert['detail']}\n")
        self.file.write(line)
        self.file.flush()

    def close(self):
        self.file.write(f"\nSession ended: {datetime.now()}\n")
        self.file.close()
