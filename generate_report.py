import pandas as pd
from datetime import datetime

def generate_report(data):
    if not data:
        print("⚠️ No vulnerabilities found. Report will not be generated.")
        return

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"vulnerability_report_{timestamp}.csv"
    
    df = pd.DataFrame(data)
    df.to_csv(filename, index=False)
    
    print(f"📜 Report generated: {filename}")
