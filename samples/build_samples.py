"""
Generates realistic sample files for Shadow Protocol triage and demonstration:
- cerberus_banking_trojan.apk (Banking Trojan with Overlays & SMS Stealer)
- spy_rat_malware.apk (Spyware with Audio/Camera/GPS & Telegram C2)
- clean_calculator.apk (Benign Android Utility)
- sample_invoice_dropper.exe (Packed PE Dropper matching PPT Slide 10)
"""
import zipfile
import io
import os
import random

SAMPLES_DIR = os.path.join(os.path.dirname(__file__))

def create_apk(filename, manifest_content, dex_content, cert_content="Android Debug"):
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", manifest_content)
        z.writestr("classes.dex", dex_content)
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nCreated-By: Android Gradle Plugin\n")
        z.writestr("META-INF/CERT.RSA", cert_content)
        z.writestr("res/layout/activity_main.xml", "<LinearLayout></LinearLayout>")
    
    out_path = os.path.join(SAMPLES_DIR, filename)
    with open(out_path, "wb") as f:
        f.write(zip_buffer.getvalue())
    print(f"Created sample APK: {out_path} ({len(zip_buffer.getvalue())} bytes)")

def generate_samples():
    os.makedirs(SAMPLES_DIR, exist_ok=True)
    
    # 1. Cerberus Banking Trojan APK
    cerberus_manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.secure.banking.auth"
    android:versionCode="204"
    android:versionName="2.4.1">
    
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
    <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.RECEIVE_SMS" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.BIND_DEVICE_ADMIN" />
    <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />
    <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES" />

    <application android:label="Secure Bank Authenticator" android:icon="@drawable/icon">
        <service android:name="com.cerberus.core.OverlayService" android:exported="true" />
        <service android:name="com.cerberus.accessibility.KeyloggerService"
            android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE">
            <intent-filter>
                <action android:name="android.accessibilityservice.AccessibilityService" />
            </intent-filter>
        </service>
        <receiver android:name="com.cerberus.receiver.BootReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
        <receiver android:name="com.cerberus.receiver.SmsReceiver" android:exported="true">
            <intent-filter android:priority="999">
                <action android:name="android.provider.Telephony.SMS_RECEIVED" />
            </intent-filter>
        </receiver>
    </application>
</manifest>"""

    cerberus_dex = """
    Lcom/cerberus/core/OverlayService;
    android/telephony/SmsManager
    sendTextMessage
    getAllMessagesFromPdu
    android/accessibilityservice/AccessibilityService
    performAction(GLOBAL_ACTION
    TYPE_APPLICATION_OVERLAY
    SYSTEM_ALERT_WINDOW
    DeviceAdminReceiver
    DevicePolicyManager
    lockNow
    Runtime;->exec
    /system/bin/sh
    /system/bin/su
    DexClassLoader
    java/lang/reflect/Method;->invoke
    https://cerberus-command.darknet-nexus.cc/api/v2/bot/register
    https://bank-credential-collector.firebaseio.com
    http://194.26.29.112:8080/sync
    AIzaSyD9a8sd7f98as7df89a7sdf987as9d8f7as
    AKIAIOSFODNN7EXAMPLE
    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkNlcmJlcnVzQm90IiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
    """ + ("\x00" * 400) + ("\xFF\xAA\xBB\xCC\xDD\xEE\x11\x22\x33\x44" * 1500)

    create_apk("cerberus_banking_trojan.apk", cerberus_manifest, cerberus_dex, "Android Debug Certificate CN=DebugKey")

    # 2. Spyware RAT Stealer APK
    spy_manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.system.android.update.service"
    android:versionCode="12"
    android:versionName="1.2">
    
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.READ_CALL_LOG" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />

    <application android:label="Google System Service">
        <service android:name="com.rat.spy.SurveillanceService" />
        <receiver android:name="com.rat.spy.BootHandler" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
    </application>
</manifest>"""

    spy_dex = """
    AudioRecord
    MediaRecorder
    android/hardware/Camera
    LocationManager
    getLastKnownLocation
    requestLocationUpdates
    ClipboardManager
    https://api.telegram.org/bot6829104829:AAFt5_9s8df76as8df76as8df76as8df76/sendMessage
    https://spyware-exfil-node.online/drop
    185.220.101.5
    """ + ("\x00" * 200) + ("\x88\x99\xAA\xBB\xCC\xDD" * 800)

    create_apk("spy_rat_malware.apk", spy_manifest, spy_dex, "Android Debug")

    # 3. Clean Calculator APK (Benign)
    clean_manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.simplemobiletools.calculator"
    android:versionCode="105"
    android:versionName="5.3.1">
    
    <uses-permission android:name="android.permission.VIBRATE" />

    <application android:label="Simple Calculator" android:icon="@drawable/calc_icon">
        <activity android:name="com.simplemobiletools.calculator.activities.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>"""

    clean_dex = """
    Lcom/simplemobiletools/calculator/activities/MainActivity;
    android.widget.Button
    android.widget.TextView
    java.lang.Math.sqrt
    java.lang.Math.sin
    java.lang.Math.cos
    """ + ("Clean bytecode text calculations and math functions only." * 50)

    create_apk("clean_calculator.apk", clean_manifest, clean_dex, "CN=SimpleMobileTools, O=OpenSource, C=CZ")

    # 4. Sample Invoice Dropper PE (.exe) matching PPT Slide 10
    # MZ header with CreateRemoteThread, VirtualAlloc, high entropy
    pe_stub = bytearray(b"MZ" + b"\x90" * 58 + b"\x80\x00\x00\x00" + b"\x00" * 64 + b"PE\x00\x00\x4c\x01\x03\x00")
    # Add imports text
    pe_stub.extend(b"KERNEL32.dll\x00CreateRemoteThread\x00VirtualAlloc\x00WriteProcessMemory\x00URLDownloadToFileA\x00")
    # Add high entropy random bytes to achieve 7.9/8 entropy as stated in PPT slide 10!
    random.seed(1337)
    high_entropy_bytes = bytes([random.randint(0, 255) for _ in range(35000)])
    pe_stub.extend(high_entropy_bytes)
    
    exe_path = os.path.join(SAMPLES_DIR, "sample_invoice.exe")
    with open(exe_path, "wb") as f:
        f.write(pe_stub)
    print(f"Created sample PE: {exe_path} ({len(pe_stub)} bytes)")

if __name__ == "__main__":
    generate_samples()
