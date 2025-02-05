import cv2
import face_recognition
import numpy as np
import os
import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import time

KNOWN_FACES_DIR = 'known_faces'

if not os.path.exists(KNOWN_FACES_DIR):
    os.makedirs(KNOWN_FACES_DIR)

class FaceRecognitionApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Face Recognition App")

        self.master.geometry("600x500")
        self.master.config(bg="#f0f0f0")  

        self.label = tk.Label(master, text="Enter your name:", font=("Arial", 12), bg="#f0f0f0")
        self.label.pack(pady=10)

        self.username_entry = tk.Entry(master, font=("Arial", 14), bd=2, relief="solid", width=20)
        self.username_entry.pack(pady=10)

        self.register_button = tk.Button(master, text="Register", command=self.register, font=("Arial", 12), bg="#4CAF50", fg="white", relief="raised", width=20)
        self.register_button.pack(pady=10)

        self.login_button = tk.Button(master, text="Login", command=self.login, font=("Arial", 12), bg="#008CBA", fg="white", relief="raised", width=20)
        self.login_button.pack(pady=10)

        self.video_frame = tk.Label(master)
        self.video_frame.pack(pady=20)

        self.video_source = 0
        self.known_face_encodings = []
        self.known_face_names = []
        self.recognized_user = None
        self.video_capture = None
        self.user_recognized_once = False
        self.recognition_interval = 5
        self.last_recognition_time = 0

        self.load_known_faces()

    def load_known_faces(self):
        for filename in os.listdir(KNOWN_FACES_DIR):
            if filename.endswith('.jpg'):
                img_path = os.path.join(KNOWN_FACES_DIR, filename)
                image = face_recognition.load_image_file(img_path)
                encoding = face_recognition.face_encodings(image)[0]
                self.known_face_encodings.append(encoding)
                self.known_face_names.append(os.path.splitext(filename)[0])

    def register(self):
        username = self.username_entry.get().strip()
        if username:
            if username + '.jpg' in os.listdir(KNOWN_FACES_DIR):
                messagebox.showerror("Error", "User already registered.")
            else:
                self.video_capture = cv2.VideoCapture(self.video_source)
                ret, frame = self.video_capture.read()
                if ret:
                    frame = cv2.flip(frame, 1)
                    rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

                    face_locations = face_recognition.face_locations(rgb_frame)
                    face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)

                    if face_encodings:
                        new_face_encoding = face_encodings[0]

                        matches = face_recognition.compare_faces(self.known_face_encodings, new_face_encoding)
                        if True in matches:
                            messagebox.showerror("Error", "Face already registered with a different name.")
                        else:
                            img_path = os.path.join(KNOWN_FACES_DIR, f"{username}.jpg")
                            cv2.imwrite(img_path, frame)
                            self.known_face_encodings.append(new_face_encoding)
                            self.known_face_names.append(username)
                            messagebox.showinfo("Success", f"User '{username}' registered successfully!")
                    else:
                        messagebox.showerror("Error", "No face detected. Please try again.")

                self.video_capture.release()
                self.username_entry.delete(0, tk.END)
        else:
            messagebox.showerror("Error", "Please enter a name.")

    def login(self):
        username = self.username_entry.get().strip()
        if username in self.known_face_names:
            self.recognized_user = username
            self.user_recognized_once = False
            self.start_video_recognition()
        else:
            messagebox.showerror("Error", "User not found. Please register first.")

    def start_video_recognition(self):
        self.video_capture = cv2.VideoCapture(self.video_source)
        self.update_video_frame()

    def update_video_frame(self):
        ret, frame = self.video_capture.read()
        if ret:
            frame = cv2.flip(frame, 1)
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

            current_time = time.time()
            if current_time - self.last_recognition_time >= self.recognition_interval:
                self.last_recognition_time = current_time
                face_locations = face_recognition.face_locations(rgb_frame)
                face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)

                for (top, right, bottom, left), face_encoding in zip(face_locations, face_encodings):
                    matches = face_recognition.compare_faces(self.known_face_encodings, face_encoding)
                    name = "Unknown"

                    if True in matches:
                        first_match_index = matches.index(True)
                        name = self.known_face_names[first_match_index]

                        if name == self.recognized_user and not self.user_recognized_once:
                            messagebox.showinfo("Recognition", f"User '{name}' recognized!")
                            self.user_recognized_once = True

                        if name == self.recognized_user:
                            self.tracked_face_location = (top, right, bottom, left)

            if self.user_recognized_once and hasattr(self, 'tracked_face_location'):
                top, right, bottom, left = self.tracked_face_location
                cv2.rectangle(frame, (left, top), (right, bottom), (0, 255, 0), 2)
                cv2.putText(frame, self.recognized_user, (left, top - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (36, 255, 12), 2)

            frame_rgb = Image.fromarray(frame)
            frame_tk = ImageTk.PhotoImage(frame_rgb)

            self.video_frame.config(image=frame_tk)
            self.video_frame.image = frame_tk

        self.master.after(10, self.update_video_frame)

    def close(self):
        if self.video_capture:
            self.video_capture.release()
        cv2.destroyAllWindows()
        self.master.quit()

if __name__ == "__main__":
    root = tk.Tk()
    app = FaceRecognitionApp(root)
    root.protocol("WM_DELETE_WINDOW", app.close)
    root.mainloop()
