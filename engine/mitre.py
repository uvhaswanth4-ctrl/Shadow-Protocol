"""
MITRE ATT&CK Mobile and Enterprise Framework Mapping for Shadow Protocol
"""

MITRE_TECHNIQUES = {
    "T1417": {
        "id": "T1417",
        "name": "Input Capture: Keylogging & Touch",
        "tactic": "Credential Access / Collection",
        "description": "Abuse of Accessibility Services or overlay windows to log keystrokes and capture credentials."
    },
    "T1444": {
        "id": "T1444",
        "name": "Screen Capture / Overlay Injection",
        "tactic": "Credential Access",
        "description": "Displaying fraudulent overlays above legitimate banking or social applications to steal login tokens."
    },
    "T1582": {
        "id": "T1582",
        "name": "SMS Interception & OTP Theft",
        "tactic": "Credential Access / Defense Evasion",
        "description": "Intercepting incoming SMS broadcasts to steal 2FA OTP codes and exfiltrate to C2."
    },
    "T1418": {
        "id": "T1418",
        "name": "Application Discovery",
        "tactic": "Discovery",
        "description": "Querying installed packages to identify targeted financial, banking, and crypto-wallet apps."
    },
    "T1624": {
        "id": "T1624",
        "name": "Event-Triggered Execution: Boot Completed",
        "tactic": "Persistence",
        "description": "Registering RECEIVE_BOOT_COMPLETED receiver to ensure malware automatically starts on device reboot."
    },
    "T1406": {
        "id": "T1406",
        "name": "Obfuscated / Packed Code",
        "tactic": "Defense Evasion",
        "description": "Employing packers, dynamic class loading (DexClassLoader), and encrypted strings to hinder static triage."
    },
    "T1437": {
        "id": "T1437",
        "name": "Exploitation of Device Administrator Privileges",
        "tactic": "Defense Evasion / Persistence",
        "description": "Requesting BIND_DEVICE_ADMIN to prevent uninstallation and enforce persistence."
    },
    "T1430": {
        "id": "T1430",
        "name": "Location Tracking",
        "tactic": "Collection",
        "description": "Acquiring GPS fine/coarse coordinates to track victim physical movements."
    },
    "T1429": {
        "id": "T1429",
        "name": "Audio / Video Capture (Spyware)",
        "tactic": "Collection",
        "description": "Accessing microphone and camera secretly without user awareness."
    },
    "T1071": {
        "id": "T1071",
        "name": "Standard Application Layer Protocol (C2)",
        "tactic": "Command and Control",
        "description": "Exfiltrating sensitive data and receiving remote commands over HTTP, HTTPS, or Firebase."
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Executing root or shell commands (su, /system/bin/sh, Runtime.getRuntime().exec)."
    },
    "T1027": {
        "id": "T1027",
        "name": "Obfuscated Files or Information (PE)",
        "tactic": "Defense Evasion",
        "description": "High entropy sections, encrypted payloads, and packed binary headers."
    },
    "T1055": {
        "id": "T1055",
        "name": "Process Injection (PE)",
        "tactic": "Privilege Escalation / Defense Evasion",
        "description": "Using VirtualAlloc, CreateRemoteThread, and WriteProcessMemory to inject malicious code."
    }
}

def map_behaviors_to_mitre(behaviors):
    """
    Given a set of identified behaviors or flags, returns structured MITRE techniques.
    """
    mapped = []
    seen = set()
    
    triggers = {
        "accessibility_abuse": "T1417",
        "overlay_detected": "T1444",
        "sms_stealer": "T1582",
        "app_enumeration": "T1418",
        "boot_persistence": "T1624",
        "dynamic_code_loading": "T1406",
        "packer_detected": "T1406",
        "device_admin": "T1437",
        "location_tracking": "T1430",
        "audio_video_capture": "T1429",
        "c2_exfiltration": "T1071",
        "firebase_backend": "T1071",
        "shell_execution": "T1059",
        "high_entropy": "T1027",
        "process_injection": "T1055"
    }
    
    for key, tech_id in triggers.items():
        if key in behaviors and tech_id not in seen:
            if tech_id in MITRE_TECHNIQUES:
                mapped.append(MITRE_TECHNIQUES[tech_id])
                seen.add(tech_id)
                
    return mapped
