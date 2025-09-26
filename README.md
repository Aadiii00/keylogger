Cybersecurity Research Tool
A dual-function cybersecurity tool developed in Python to research system-level data monitoring and threat detection. This project was completed as part of the Pinnacle Labs Internship Program.

Overview
This tool was designed to fulfill the 

Keylogger Software project task, which emphasizes security research and protection against keyloggers. It demonstrates both offensive data-capturing techniques and defensive measures, all managed through a user-friendly GUI. The application captures detailed user activity and secures the collected data using symmetric encryption, providing a complete educational cycle from data collection to data protection and threat analysis.

Key Features
Structured Keystroke Logging: Intelligently captures keyboard input and formats it into readable words and lines, rather than individual, difficult-to-read characters.

Active Window Tracking: Provides crucial operational context by logging the title of the active application (e.g., "Google Chrome," "Notepad") where the typing occurs.

Periodic Screenshot Captures: Automatically takes screenshots of the user's desktop at configurable intervals for comprehensive visual monitoring and analysis.

Log File Encryption: To ensure data security, all captured keystrokes are automatically encrypted using the Fernet (AES128) symmetric encryption scheme when monitoring is stopped.

Integrated Threat Detector: Includes a defensive function that can scan for the tool's own traces (the presence of the encrypted log file) to simulate anti-keylogger behavior.

GUI Control Panel: A clean and intuitive interface built with Tkinter that allows a user to start/stop all services, enable/disable features, and securely view the decrypted logs in-app.

Technology Stack

Language: Python
GUI: Tkinter
System Monitoring: pynput, pywin32
Data Handling: Pillow (for images), cryptography (for encryption)
Concurrency: threading (to ensure a non-blocking GUI)

Setup & Usage
To get this project running on your local machine, follow these steps.

1. Prerequisites
Ensure you have Python 3 installed on your system.

2. Clone the Repository
Bash
git clone https://github.com/YourUsername/Cybersecurity-Research-Tool.git
cd Cybersecurity-Research-Tool

4. Install Dependencies
Install all the required libraries using pip.
Bash
pip install pynput pillow pywin32 cryptography

5. Generate Encryption Key
Run the key generation script one time to create your unique secret key.
Bash
python generate_key.py

6. Launch the Application
You are now ready to run the main application.
python gui_app.py

Ethical Disclaimer
This tool was developed strictly for educational and security research purposes. The goal is to better understand how certain classes of malware operate in order to build better defenses. It should not be used for any unauthorized or malicious activities. The author is not responsible for any misuse of this software.
