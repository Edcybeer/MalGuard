import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import requests
import hashlib
import time
import os
import cv2
import face_recognition
import numpy as np
from PIL import Image, ImageTk

# VirusTotal API Key
API_KEY = ""  # Replace with your actual API key

# Face Recognition Constants
KNOWN_FACES_DIR = 'known_faces'
if not os.path.exists(KNOWN_FACES_DIR):
    os.makedirs(KNOWN_FACES_DIR)


def load_known_faces():
    """Loads known face encodings and names."""
    known_face_encodings = []
    known_face_names = []
    for filename in os.listdir(KNOWN_FACES_DIR):
        if filename.endswith('.jpg'):
            img_path = os.path.join(KNOWN_FACES_DIR, filename)
            image = face_recognition.load_image_file(img_path)
            encoding = face_recognition.face_encodings(image)[0]
            known_face_encodings.append(encoding)
            known_face_names.append(os.path.splitext(filename)[0])
    return known_face_encodings, known_face_names


def register_face(username, video_source=0):
    """Registers a new user's face."""
    video_capture = cv2.VideoCapture(video_source)
    messagebox.showinfo("Face Registration", "Look into the camera to register your face.")
    time.sleep(2)  # Brief pause for the user
    ret, frame = video_capture.read()
    if ret:
        frame = cv2.flip(frame, 1)
        img_path = os.path.join(KNOWN_FACES_DIR, f"{username}.jpg")
        cv2.imwrite(img_path, frame)
        video_capture.release()
        messagebox.showinfo("Success", f"User '{username}' registered successfully!")
        return True
    else:
        video_capture.release()
        messagebox.showerror("Error", "Could not capture face. Try again.")
        return False


def recognize_face(known_face_encodings, known_face_names, video_source=0):
    """Recognizes a face from the video feed."""
    video_capture = cv2.VideoCapture(video_source)
    while True:
        ret, frame = video_capture.read()
        if not ret:
            messagebox.showerror("Error", "Unable to access camera.")
            video_capture.release()
            return None
        frame = cv2.flip(frame, 1)
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        face_locations = face_recognition.face_locations(rgb_frame)
        face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)

        for face_encoding in face_encodings:
            matches = face_recognition.compare_faces(known_face_encodings, face_encoding)
            if True in matches:
                match_index = matches.index(True)
                video_capture.release()
                return known_face_names[match_index]

        # Show live video feed with prompt
        cv2.putText(frame, "Looking for a registered face...", (10, 30),
                    cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)
        cv2.imshow("Face Recognition", frame)

        # Break loop on 'q' key press
        if cv2.waitKey(1) & 0xFF == ord('q'):
            video_capture.release()
            cv2.destroyAllWindows()
            return None


# Pre-check with face recognition
def face_recognition_precheck():
    """Runs the face recognition check before launching the app."""
    known_face_encodings, known_face_names = load_known_faces()
    if not known_face_encodings:
        response = messagebox.askyesno("No Registered Faces",
                                       "No known faces found. Would you like to register the admin face now?")
        if response:
            admin_name = simpledialog.askstring("Register Admin", "Enter admin name:")
            if admin_name:
                if register_face(admin_name):
                    known_face_encodings, known_face_names = load_known_faces()
                else:
                    return False
            else:
                messagebox.showwarning("Registration Cancelled", "No face registered. Exiting application.")
                return False
        else:
            return False

    # Attempt to recognize a face
    recognized_user = recognize_face(known_face_encodings, known_face_names)
    if not recognized_user:
        messagebox.showwarning("Access Denied", "No registered face recognized. Exiting application.")
        return False
    else:
        messagebox.showinfo("Access Granted", f"Welcome, {recognized_user}!")
        return True


# Run Face Recognition Pre-check
if not face_recognition_precheck():
    exit()


# Function to calculate file hash
def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


# Function to scan the file using VirusTotal API
def scan_file(file_path):
    file_hash = calculate_file_hash(file_path)
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        return parse_results(result, file_path)
    else:
        return f"Error: {response.status_code} - {response.text}"


# Function to parse the JSON response from VirusTotal and display results interactively in the popup
def parse_results(result, file_path):
    scans = result.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
    positives = sum(1 for scan in scans.values() if scan["category"] == "malicious")
    total_engines = len(scans)
    detection_ratio = (positives / total_engines) * 100 if total_engines > 0 else 0
    file_size_kb = os.path.getsize(file_path) / 1024  # Get file size in KB

    # Create result string for all engines (Main window)
    all_results_text = f"File: {os.path.basename(file_path)}\n"
    all_results_text += f"Detection Ratio: {positives}/{total_engines} ({detection_ratio:.2f}%)\n"
    all_results_text += f"File Size: {file_size_kb:.2f} KB\n\n"

    for engine, scan_result in scans.items():
        all_results_text += f"{engine}: {scan_result['category']} - {scan_result['result']}\n"

    # Create result string for malicious engines (Popup window)
    malicious_results = []
    for engine, scan_result in scans.items():
        if scan_result["category"] == "malicious":
            malicious_results.append(f"{engine}: {scan_result['category']} - {scan_result['result']}")

    return all_results_text, malicious_results, scans


# Function to display results interactively in a Text widget
def display_results():
    file_path = filedialog.askopenfilename()
    if file_path:
        try:
            all_results_text, malicious_results, scans = scan_file(file_path)

            # Update main window with all results
            file_info.config(text=all_results_text)

            # Create a new popup window for malicious results
            result_popup = tk.Toplevel(root)
            result_popup.title("Malicious Scan Results")
            result_popup.geometry("600x400")

            result_popup.configure(bg="#000000")

            # Add a scrollable text box to display malicious results
            result_box = tk.Text(result_popup, wrap=tk.WORD, bg="#000000", fg="red", font=("Arial", 12))
            result_box.pack(padx=10, pady=10, fill="both", expand=True)

            # Display only malicious results in the popup
            for malicious in malicious_results:
                result_box.insert(tk.END, malicious + "\n")
            
            result_box.config(state=tk.DISABLED)  # Make the text box read-only

            # Add a close button to the popup
            close_button = tk.Button(result_popup, text="Close", command=result_popup.destroy, bg="#0078D4", fg="white")
            close_button.pack(pady=10)

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")


# Function to disconnect from the API
def disconnect_api():
    global API_KEY
    API_KEY = ""
    messagebox.showinfo("Disconnect", "Disconnected from the API.")


# Function to change API key
def change_api():
    global API_KEY
    new_api_key = simpledialog.askstring("Change API Key", "Enter new API Key:")
    if new_api_key:
        API_KEY = new_api_key
        messagebox.showinfo("API Key Changed", "API Key has been successfully changed.")


# Additional menu functions
def about():
    messagebox.showinfo("About", "XKSH - Cybersecurity Scanner\nVersion 1.5\nA tool for scanning files and detecting security threats.")


def settings():
    messagebox.showinfo("Settings", "Settings options would be here.")


def account():
    messagebox.showinfo("Account", "Manage your account details here.")


def help_info():
    messagebox.showinfo("Help", "Help documentation and support resources.")


def report_issue():
    messagebox.showinfo("Report an Issue", "Report any issues or bugs you encounter.")


def sign_out():
    messagebox.showinfo("Sign Out", "You have been signed out.")


# Set up the main window
root = tk.Tk()
root.title("XKSH - Cybersecurity Scanner")

# Set the window icon (use a .ico file)
root.iconbitmap("security-check.ico")  # Replace with the path to your .ico file

root.attributes("-fullscreen", True)

# Optionally, add a way to exit full-screen mode (e.g., pressing 'Esc')
def exit_fullscreen(event=None):
    root.attributes("-fullscreen", False)

# Bind the 'Esc' key to exit full screen
root.bind("<Escape>", exit_fullscreen)
root.configure(bg="#000000")  # Black background

# Configure grid for responsiveness
root.grid_columnconfigure(1, weight=1)
root.grid_rowconfigure(0, weight=1)

# Left sidebar
sidebar = tk.Frame(root, bg="#000000", width=200, height=500)
sidebar.grid(row=0, column=0, sticky="ns")

# Add logo to sidebar
logo_image = Image.open("logo.png")  # Replace with your logo file
logo_image = logo_image.resize((150, 150), Image.Resampling.LANCZOS)
logo_photo = ImageTk.PhotoImage(logo_image)
logo_label = tk.Label(sidebar, image=logo_photo, bg="#000000")
logo_label.pack(pady=20)

# Button container for sidebar
button_container = tk.Frame(sidebar, bg="#000000")
button_container.pack(expand=True)

# Create and place buttons in sidebar
about_button = tk.Button(button_container, text="About", bg="#0078D4", fg="white", font=("Arial", 14), relief="flat", command=about)
about_button.pack(fill="x", padx=10, pady=5)

settings_button = tk.Button(button_container, text="Settings", bg="#0078D4", fg="white", font=("Arial", 14), relief="flat", command=settings)
settings_button.pack(fill="x", padx=10, pady=5)

account_button = tk.Button(button_container, text="Account", bg="#0078D4", fg="white", font=("Arial", 14), relief="flat", command=account)
account_button.pack(fill="x", padx=10, pady=5)

help_button = tk.Button(button_container, text="Help", bg="#0078D4", fg="white", font=("Arial", 14), relief="flat", command=help_info)
help_button.pack(fill="x", padx=10, pady=5)

report_button = tk.Button(button_container, text="Report an Issue", bg="#0078D4", fg="white", font=("Arial", 14), relief="flat", command=report_issue)
report_button.pack(fill="x", padx=10, pady=5)

sign_out_button = tk.Button(button_container, text="Sign Out", bg="#0078D4", fg="white", font=("Arial", 14), relief="flat", command=sign_out)
sign_out_button.pack(fill="x", padx=10, pady=5)

# Scan button placed as a sidebar button
scan_button = tk.Button(button_container, text="Scan File", bg="#0078D4", fg="white", font=("Arial", 14), relief="flat", command=display_results)
scan_button.pack(fill="x", padx=10, pady=5)

# File information label
file_info = tk.Label(root, text="", bg="#000000", fg="white", font=("Arial", 12))
file_info.grid(row=1, column=1, padx=10, pady=5, sticky="w")

root.mainloop()
