# Steganography App

## Overview
This Steganography App enables users to securely encode and decode text messages within image files. Utilizing encryption and the Least Significant Bit (LSB) steganography technique, this app hides messages in images, which can be retrieved with the correct password. This tool is ideal for secure and private message storage in image files.

## Features
- **Encode Messages:** Select an image, enter a message, and password-protect it with encryption.
- **Decode Messages:** Retrieve encoded messages from images by entering the correct password.
- **Password-Based Encryption:** Uses SHA-256 to hash passwords, creating encryption keys via Fernet from the `cryptography` library.
- **Dynamic Feedback:** Provides real-time feedback on message length relative to the image’s storage capacity.

## Installation

1. **Requirements:** Ensure you have Python 3 installed.
2. **Clone the Repository:** Download or clone this project.
3. **Install Dependencies:** 
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. **Run the Application:**
   ```bash
   python main.py

## Encode Tab
- **Select an image** for encoding (JPEG or PNG format).
- **Enter a message** and a password.
- **Click "Encode Message"** to save the image with the hidden message.

## Decode Tab
- **Select an encoded image**.
- **Enter the password** used during encoding.
- **Click "Decode Message"** to retrieve the original message.

## How It Works

### Key Components
- **`generate_key(password)`**: Hashes a password using SHA-256, creating a 32-byte base64-encoded encryption key.
- **`encrypt_message(message, key)`**: Encrypts the message with the generated key using Fernet symmetric encryption.
- **`decrypt_message(encrypted_message, key)`**: Decrypts the message using the key.
- **`max_message_size(image_path)`**: Determines the maximum message size that can be stored in the selected image.

### Encoding and Decoding Process

- **Encoding**:
  - Encrypts the input message with the user-defined password.
  - Converts encrypted message bits into binary and stores them in the Least Significant Bits (LSB) of the image's RGB channels.

- **Decoding**:
  - Extracts binary data from the image's LSB.
  - Rebuilds the encrypted message, decrypts it using the password, and displays the hidden message.

## Requirements

- **`customtkinter`**: For enhanced GUI elements.
- **`tkinter`**: Provides basic GUI functionality.
- **`PIL (Pillow)`**: For image processing.
- **`cryptography`**: For encrypting and decrypting messages.

## Example Commands

```python
# Generate encryption key
generate_key("password123")

# Encrypt a message
encrypt_message("This is a secret message", key)

# Decrypt a message
decrypt_message(encrypted_message, key)
```
## Contact

If you have any questions, suggestions, or need assistance with this project, feel free to reach out:

**Email:** [samuellabant@gmail.com](mailto:samuellabant@gmail.com)

## License

This project is licensed under the **Unrestricted License**. Please see the [License](#license) section for more details on usage rights and limitations.
