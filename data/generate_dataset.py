"""
Generates realistic EMBER & Drebin malware triage benchmark dataset for Shadow Protocol
"""
import csv
import random
import os

DATASET_PATH = os.path.join(os.path.dirname(__file__), "malware_dataset.csv")

def generate_dataset(num_samples=1200):
    headers = [
        "sample_id", "entropy", "file_size_kb", "dangerous_permissions",
        "suspicious_permissions", "suspicious_apis", "secrets_count", "urls_count",
        "has_accessibility", "has_overlay", "has_sms", "has_boot_receiver",
        "is_packed", "exported_components_count", "target_label", "malware_family"
    ]
    
    families_mal = ["Cerberus Banking Trojan", "Anubis Spyware", "WannaCry Dropper", "SharkBot Overlay", "Joker Adware", "Pegasus RAT"]
    families_ben = ["Clean Productivity Tool", "Standard Android Utility", "Calculator App", "Weather Widget", "Audio Player"]
    
    random.seed(42)
    rows = []
    
    for i in range(num_samples):
        is_mal = 1 if i % 2 == 0 else 0
        sid = f"SAMPLE_{i+1000:04d}"
        
        if is_mal:
            entropy = round(random.uniform(6.8, 7.98), 2)
            file_size_kb = random.randint(150, 8500)
            dangerous_perms = random.randint(3, 12)
            suspicious_perms = random.randint(2, 6)
            suspicious_apis = random.randint(3, 14)
            secrets = random.randint(1, 6)
            urls = random.randint(2, 18)
            has_acc = 1 if random.random() > 0.3 else 0
            has_over = 1 if random.random() > 0.35 else 0
            has_sms = 1 if random.random() > 0.4 else 0
            has_boot = 1 if random.random() > 0.25 else 0
            is_packed = 1 if random.random() > 0.4 else 0
            exported_comps = random.randint(2, 9)
            family = random.choice(families_mal)
        else:
            entropy = round(random.uniform(4.0, 6.2), 2)
            file_size_kb = random.randint(50, 4200)
            dangerous_perms = random.randint(0, 2)
            suspicious_perms = 0 if random.random() > 0.1 else 1
            suspicious_apis = random.randint(0, 2)
            secrets = 0 if random.random() > 0.2 else 1
            urls = random.randint(0, 5)
            has_acc = 0
            has_over = 0
            has_sms = 0
            has_boot = 0 if random.random() > 0.15 else 1
            is_packed = 0
            exported_comps = random.randint(0, 2)
            family = random.choice(families_ben)
            
        rows.append([
            sid, entropy, file_size_kb, dangerous_perms, suspicious_perms,
            suspicious_apis, secrets, urls, has_acc, has_over, has_sms,
            has_boot, is_packed, exported_comps, is_mal, family
        ])
        
    os.makedirs(os.path.dirname(DATASET_PATH), exist_ok=True)
    with open(DATASET_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
        
    print(f"Generated {num_samples} records in {DATASET_PATH}")

if __name__ == "__main__":
    generate_dataset()
