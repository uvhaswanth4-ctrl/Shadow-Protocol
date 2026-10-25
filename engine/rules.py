"""
YARA-style heuristic signature and taxonomy rules for Shadow Protocol
"""
import re

# Android Permissions Categorization
PERMISSION_CATEGORIES = {
    "DANGEROUS": {
        "android.permission.READ_SMS": "Allows app to read stored SMS messages (OTP / 2FA theft)",
        "android.permission.SEND_SMS": "Allows app to send SMS (premium SMS fraud / C2 dispatch)",
        "android.permission.RECEIVE_SMS": "Allows app to intercept incoming SMS broadcasts",
        "android.permission.RECEIVE_MMS": "Allows app to monitor incoming MMS messages",
        "android.permission.READ_CONTACTS": "Allows access to address book / contact exfiltration",
        "android.permission.WRITE_CONTACTS": "Allows modifying address book",
        "android.permission.READ_CALL_LOG": "Allows reading victim call history",
        "android.permission.WRITE_CALL_LOG": "Allows modifying call history",
        "android.permission.PROCESS_OUTGOING_CALLS": "Allows redirecting or eavesdropping on calls",
        "android.permission.CALL_PHONE": "Allows dialing phone numbers without confirmation",
        "android.permission.ACCESS_FINE_LOCATION": "Precise GPS geographical location tracking",
        "android.permission.ACCESS_COARSE_LOCATION": "Cellular/WiFi network location tracking",
        "android.permission.RECORD_AUDIO": "Audio recording / microphone eavesdropping",
        "android.permission.CAMERA": "Unauthorized photo and video capture",
        "android.permission.READ_EXTERNAL_STORAGE": "Reading photos, documents, and external files",
        "android.permission.WRITE_EXTERNAL_STORAGE": "Writing/encrypting files (Ransomware risk)",
        "android.permission.MANAGE_EXTERNAL_STORAGE": "Full unconstrained file system access"
    },
    "SUSPICIOUS": {
        "android.permission.SYSTEM_ALERT_WINDOW": "Overlay window creation over banking/social apps (Phishing)",
        "android.permission.BIND_ACCESSIBILITY_SERVICE": "Accessibility service hijacking (Keylogger, Auto-clicks)",
        "android.permission.BIND_DEVICE_ADMIN": "Device administrator lock-in (Prevents uninstall)",
        "android.permission.REQUEST_INSTALL_PACKAGES": "Silently downloading and installing secondary dropper payloads",
        "android.permission.INSTALL_PACKAGES": "System package installer privilege abuse",
        "android.permission.RECEIVE_BOOT_COMPLETED": "Auto-start persistence after device reboot",
        "android.permission.QUERY_ALL_PACKAGES": "Reconnaissance: scans device for banking/crypto wallets",
        "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": "Keeps malware active indefinitely in background",
        "android.permission.READ_LOGS": "Reads system logcat to steal tokens or credentials",
        "android.permission.WRITE_SETTINGS": "Modifies system security configurations",
        "android.permission.DISABLE_KEYGUARD": "Unlocks screen without user knowledge",
        "android.permission.ACCESS_BACKGROUND_LOCATION": "Secret 24/7 background geotracking"
    },
    "NORMAL": {
        "android.permission.INTERNET": "Basic network access",
        "android.permission.ACCESS_NETWORK_STATE": "View network connection status",
        "android.permission.ACCESS_WIFI_STATE": "View Wi-Fi connection status",
        "android.permission.VIBRATE": "Haptic feedback",
        "android.permission.WAKE_LOCK": "Prevent processor from sleeping",
        "android.permission.FOREGROUND_SERVICE": "Runs background foreground service",
        "android.permission.POST_NOTIFICATIONS": "Display notification icons"
    }
}

# Suspicious API and Code Signatures
SUSPICIOUS_APIS = [
    {
        "id": "API_SMS_MANAGER",
        "name": "SmsManager Telephony Interception",
        "pattern": r"(android/telephony/SmsManager|sendTextMessage|getAllMessagesFromPdu)",
        "severity": "CRITICAL",
        "category": "SMS / OTP Interception",
        "behavior": "sms_stealer",
        "description": "Directly interfaces with GSM/CDMA SMS stack to read, send, or steal OTP tokens."
    },
    {
        "id": "API_ACCESSIBILITY",
        "name": "AccessibilityService Hijack",
        "pattern": r"(android/accessibilityservice/AccessibilityService|AccessibilityEvent|performAction\(GLOBAL_ACTION)",
        "severity": "CRITICAL",
        "category": "Keylogging & Auto-Clicker",
        "behavior": "accessibility_abuse",
        "description": "Abuses Android Accessibility framework to read screen contents, steal passwords, and bypass 2FA."
    },
    {
        "id": "API_OVERLAY",
        "name": "Window Manager Fake Overlay",
        "pattern": r"(TYPE_APPLICATION_OVERLAY|TYPE_SYSTEM_ALERT|TYPE_SYSTEM_ERROR|SYSTEM_ALERT_WINDOW)",
        "severity": "HIGH",
        "category": "Overlay Phishing",
        "behavior": "overlay_detected",
        "description": "Injects transparent or deceptive UI windows over target banking apps to harvest PINs."
    },
    {
        "id": "API_DEVICE_ADMIN",
        "name": "Device Administrator Lockout",
        "pattern": r"(DeviceAdminReceiver|DevicePolicyManager|lockNow|resetPassword|wipeData)",
        "severity": "HIGH",
        "category": "Device Administrator",
        "behavior": "device_admin",
        "description": "Enforces root/admin persistence, disables uninstallation, or holds device hostage."
    },
    {
        "id": "API_SHELL_EXEC",
        "name": "Runtime Shell Execution",
        "pattern": r"(Runtime;\s*->\s*exec|ProcessBuilder|/system/bin/sh|/system/bin/su|\bsu\b)",
        "severity": "CRITICAL",
        "category": "Command Execution",
        "behavior": "shell_execution",
        "description": "Spawns interactive shell commands or attempts Linux root privilege escalation."
    },
    {
        "id": "API_DEX_LOADER",
        "name": "Dynamic Dex / Bytecode Loading",
        "pattern": r"(DexClassLoader|InMemoryDexClassLoader|PathClassLoader|dalvik/system/BaseDexClassLoader)",
        "severity": "HIGH",
        "category": "Packer / Obfuscation",
        "behavior": "dynamic_code_loading",
        "description": "Loads encrypted or secondary APK payloads dynamically from assets or remote servers."
    },
    {
        "id": "API_REFLECTION",
        "name": "Java Reflection & Obfuscation",
        "pattern": r"(java/lang/reflect/Method;\s*->\s*invoke|Class;\s*->\s*forName|getDeclaredMethod)",
        "severity": "MEDIUM",
        "category": "Evasion & Obfuscation",
        "behavior": "dynamic_code_loading",
        "description": "Uses reflection to hide calls to sensitive internal Android framework methods."
    },
    {
        "id": "API_CLIPBOARD",
        "name": "Clipboard Monitor / Crypto Hijack",
        "pattern": r"(ClipboardManager|getPrimaryClip|setPrimaryClip)",
        "severity": "MEDIUM",
        "category": "Clipboard Hijacking",
        "behavior": "clipboard_stealer",
        "description": "Monitors or alters clipboard data to replace cryptocurrency wallet addresses."
    },
    {
        "id": "API_AUDIO_CAMERA",
        "name": "Spyware Audio / Video Capture",
        "pattern": r"(AudioRecord|MediaRecorder|android/hardware/Camera|android/hardware/camera2)",
        "severity": "HIGH",
        "category": "Surveillance",
        "behavior": "audio_video_capture",
        "description": "Records ambient audio or captures video covertly in the background."
    },
    {
        "id": "API_LOCATION",
        "name": "GPS Geolocation Tracking",
        "pattern": r"(LocationManager|getLastKnownLocation|requestLocationUpdates|FusedLocationProviderClient)",
        "severity": "MEDIUM",
        "category": "Location Tracking",
        "behavior": "location_tracking",
        "description": "Harvests and tracks victim physical coordinates."
    },
    {
        "id": "API_PACKAGE_ENUM",
        "name": "Banking App Enumeration",
        "pattern": r"(getInstalledPackages|getInstalledApplications|getLaunchIntentForPackage)",
        "severity": "MEDIUM",
        "category": "Reconnaissance",
        "behavior": "app_enumeration",
        "description": "Discovers if legitimate banking or cryptocurrency apps are installed."
    }
]

# Hardcoded Secret and Token Regexes
SECRET_PATTERNS = [
    {"name": "Google API Key", "regex": r"AIza[0-9A-Za-z\\-_]{35}", "severity": "HIGH"},
    {"name": "AWS Access Key", "regex": r"AKIA[0-9A-Z]{16}", "severity": "CRITICAL"},
    {"name": "Firebase Database URL", "regex": r"https://[a-zA-Z0-9_-]+\.firebaseio\.com", "severity": "HIGH"},
    {"name": "Generic JWT Token", "regex": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+", "severity": "CRITICAL"},
    {"name": "Telegram Bot Token", "regex": r"[0-9]{9,10}:[a-zA-Z0-9_-]{35}", "severity": "CRITICAL"},
    {"name": "Hardcoded Private Key / RSA", "regex": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "severity": "CRITICAL"},
    {"name": "Hardcoded Password String", "regex": r"(?i)(?:password|passwd|db_pass)\s*[:=]\s*[\"'][^\"']{5,}[\"']", "severity": "HIGH"},
    {"name": "Suspicious IPv4 Address", "regex": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", "severity": "MEDIUM"}
]

# Known Android Packers & Protecters
KNOWN_PACKERS = [
    {"name": "DexGuard / ProGuard", "pattern": r"(DexGuard|com/guardsquare|a/a/a/a)"},
    {"name": "Bangcle / SecShell", "pattern": r"(libsecexe\.so|libsecmain\.so|bangcle)"},
    {"name": "Qihoo 360 Jiagu", "pattern": r"(libprotectClass\.so|libjiagu\.so)"},
    {"name": "Tencent Legu", "pattern": r"(libshex\.so|libtencent_stub\.so)"},
    {"name": "UPX Packer", "pattern": r"(UPX0|UPX1|UPX!)"},
    {"name": "Baidu Protect", "pattern": r"(libbaiduprotect\.so)"}
]

# Windows PE Suspicious Imports (for PE Static Triage)
PE_SUSPICIOUS_IMPORTS = {
    "CreateRemoteThread": {"severity": "CRITICAL", "behavior": "process_injection", "desc": "Process injection & shellcode execution"},
    "VirtualAllocEx": {"severity": "HIGH", "behavior": "process_injection", "desc": "Allocates memory space in remote process"},
    "WriteProcessMemory": {"severity": "HIGH", "behavior": "process_injection", "desc": "Writes payload into target process memory"},
    "SetWindowsHookExA": {"severity": "HIGH", "behavior": "accessibility_abuse", "desc": "Global keystroke hooking / Keylogging"},
    "InternetOpenA": {"severity": "MEDIUM", "behavior": "c2_exfiltration", "desc": "Establishes raw HTTP connection to C2 server"},
    "URLDownloadToFileA": {"severity": "HIGH", "behavior": "dynamic_code_loading", "desc": "Silent dropper downloading executable"},
    "RegSetValueExA": {"severity": "MEDIUM", "behavior": "boot_persistence", "desc": "Writes persistence run keys into registry"},
    "CryptEncrypt": {"severity": "HIGH", "behavior": "ransomware_crypto", "desc": "Symmetric/Asymmetric encryption (Ransomware)"}
}
