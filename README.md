# MalGuard: Face Recognition & Malicious File Detection

**MalGuard** is a security program that uses facial recognition for login and scans for malicious files using the VirusTotal API.

## Features
- **Face Recognition**: Uses OpenCV for facial recognition to securely log in.
- **Malware Detection**: Scans files for potential malware using the VirusTotal API.
- **Minimize Window**: Press `ESC` to minimize the window during use.
- **Folder for Face Registration**: Before using the application, you need to create a folder named `known_faces` to store registered faces for authentication.

## Requirements
1. **Folder for Known Faces**:
   - Create a folder named `known_faces` in the same directory as the program. This is where the program will store registered face data.
   
2. **Face Registration**:
   - Run the **FaceRecognition** code to register a face. 
   - **Note**: A person cannot be registered twice. If a person’s face is already registered, the program will not allow a second registration.
   
3. **VirusTotal API Key**:
   - **Important**: You need a **VirusTotal API Key** to scan files for malware. To get your API key, sign up at [VirusTotal](https://www.virustotal.com/) and generate a free key.
   - Replace the placeholder API key in the code with your actual key for the program to work.

4. **Libraries**:
   - OpenCV for facial recognition.
   - Requests for API interaction.

## Setup Instructions

1. **Clone the Repository**:
   - Clone this repository to your local machine.
   ```bash

