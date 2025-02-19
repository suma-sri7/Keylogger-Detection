import os
import time
import psutil
import subprocess
import threading
import tkinter as tk
from tkinter import messagebox
from pynput import keyboard

# Define known keylogger files and processes
SUSPICIOUS_FILES = [
    "keylog.txt", "logger.exe", "stealer.dll", "kl.dll", "capture.exe"
]

SUSPICIOUS_PROCESSES = [
    "keylogger", "hooker", "keystroke_capture", "logkeys", "winlogon"
]

# Common antivirus processes
ANTIVIRUS_PROCESSES = [
    "windows defender", "avast", "avg", "bitdefender", "mcafee",
    "norton", "kaspersky", "eset", "sophos", "trend micro", "f-secure"
]

# Keystroke timing threshold (seconds)
DELAY_THRESHOLD = 1.5

# Store keystroke timestamps and logs
keystroke_times = []
keystroke_log = []

# Flags for detection results
keylogger_detected = False
antivirus_found = False

# Tkinter window setup
root = tk.Tk()
root.title("Keylogger Detection Tool")
root.geometry("800x600")  # Increased window size
root.configure(bg="lightblue")

# Labels to display results
status_label = tk.Label(root, text="Running Full System Security Check...", font=("Arial", 16), bg="lightblue")
status_label.pack(pady=20)

result_text = tk.Text(root, height=15, width=80, bg="black", fg="white", font=("Courier", 12))
result_text.pack(pady=20)
result_text.config(state=tk.DISABLED)

# Function to update GUI with results
def update_gui(message, message_type="info"):
    result_text.config(state=tk.NORMAL)
    
    # Color based on message type
    if message_type == "info":
        result_text.insert(tk.END, message + "\n", "info")
    elif message_type == "alert":
        result_text.insert(tk.END, message + "\n", "alert")
    elif message_type == "warning":
        result_text.insert(tk.END, message + "\n", "warning")
    
    result_text.config(state=tk.DISABLED)
    result_text.yview(tk.END)

    # Color tags
    result_text.tag_config("info", foreground="green", font=("Courier", 12, "bold"))
    result_text.tag_config("alert", foreground="red", font=("Courier", 12, "bold"))
    result_text.tag_config("warning", foreground="orange", font=("Courier", 12, "bold"))

def detect_suspicious_files():
    """Check common system directories for known keylogger files."""
    global keylogger_detected
    paths_to_check = ["C:\\Windows\\System32", "C:\\Users\\Public", "C:\\Temp"]

    for path in paths_to_check:
        if os.path.exists(path):
            for file in os.listdir(path):
                if file.lower() in SUSPICIOUS_FILES:
                    message = f"[ALERT] Suspicious file detected: {file} in {path}"
                    update_gui(message, "alert")
                    keylogger_detected = True
                    return True
    return False


def detect_suspicious_processes():
    """Check if any keylogger-related processes are running."""
    global keylogger_detected
    for process in psutil.process_iter(attrs=['pid', 'name']):
        try:
            proc_name = process.info['name'].lower()
            if any(suspicious in proc_name for suspicious in SUSPICIOUS_PROCESSES):
                message = f"[ALERT] Suspicious process running: {proc_name} (PID: {process.info['pid']})"
                update_gui(message, "alert")
                keylogger_detected = True
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False


def detect_antivirus_process():
    """Check if an antivirus is running in active processes."""
    global antivirus_found
    for process in psutil.process_iter(attrs=['name']):
        try:
            proc_name = process.info['name'].lower()
            if any(av in proc_name for av in ANTIVIRUS_PROCESSES):
                message = f"✅ Antivirus detected: {proc_name}"
                update_gui(message, "info")
                antivirus_found = True
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False


def detect_antivirus_registry():
    """Check if an antivirus is installed using Windows Security Center."""
    global antivirus_found
    try:
        output = subprocess.check_output(
            'wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName',
            shell=True
        ).decode()

        av_list = output.strip().split("\n")[1:]
        av_list = [av.strip() for av in av_list if av.strip()]
        
        if av_list:
            message = f"✅ Installed Antivirus: {', '.join(av_list)}"
            update_gui(message, "info")
            antivirus_found = True
            return True
    except Exception:
        pass

    return False


def detect_keylogger_timing():
    """Analyze keystroke timing to detect abnormal delays."""
    global keylogger_detected
    if len(keystroke_times) > 1:
        time_diff = keystroke_times[-1] - keystroke_times[-2]

        # Display delay even if it's small
        message = f"Keystroke Delay: {time_diff:.2f}s"
        update_gui(message, "info")
        
        if time_diff > DELAY_THRESHOLD:
            message = f"[ALERT] Suspicious keystroke delay detected: {time_diff:.2f}s"
            update_gui(message, "alert")
            keylogger_detected = True


def on_press(key):
    """Monitor keystrokes and log their timings."""
    global keystroke_times, keystroke_log

    current_time = time.time()
    keystroke_times.append(current_time)

    # Log the key entered
    try:
        if hasattr(key, 'char') and key.char is not None:
            keystroke_log.append(key.char)
        else:
            keystroke_log.append(str(key))
    except Exception:
        keystroke_log.append("[ERROR]")

    # Update keystrokes in the GUI
    keystrokes_display = ''.join(keystroke_log[-15:])  # Show last 15 keys for better display
    update_gui(f"Keystrokes: {keystrokes_display}", "info")

    # Check for unusual typing delay
    detect_keylogger_timing()


def monitor_keystrokes():
    """Start listening for keystrokes."""
    update_gui("🛡️ Monitoring keystroke behavior... (Press ESC to exit)", "info")
    
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()


def start_detection():
    """Start the detection in a separate thread."""
    def detection_process():
        global keylogger_detected, antivirus_found

        update_gui("🔍 Running Full System Security Check...\n", "info")

        # Check for antivirus presence
        av_running = detect_antivirus_process()
        av_installed = detect_antivirus_registry()

        if not av_running and not av_installed:
            update_gui("⚠️ No active antivirus detected! Your system might be vulnerable.", "warning")
        
        # Check for keyloggers
        file_check = detect_suspicious_files()
        process_check = detect_suspicious_processes()

        # Final verdict
        if keylogger_detected:
            update_gui("\n🚨🚨 **KEYLOGGER ATTACK DETECTED!** 🚨🚨", "alert")
        else:
            update_gui("\n✅ No keyloggers detected in files or processes.", "info")

        if antivirus_found:
            if keylogger_detected:
                update_gui("\n⚠️ WARNING: Your antivirus is active, but a keylogger was still found!", "warning")
            else:
                update_gui("\n✅ Your antivirus is working properly.", "info")
        else:
            update_gui("\n⚠️ No antivirus detected! Your system is at high risk.", "warning")

        # Start keystroke monitoring
        monitor_keystrokes()

    # Start the detection process in a new thread to keep GUI responsive
    detection_thread = threading.Thread(target=detection_process)
    detection_thread.start()


# Button to start detection
start_button = tk.Button(root, text="Start Detection", font=("Arial", 16), command=start_detection, bg="blue", fg="white")
start_button.pack(pady=20)

# Run the GUI
root.mainloop()
