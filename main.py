import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
import hashlib, base64, os

# Function to generate an encryption key based on a password
def generate_key(password):
    # Use SHA-256 to hash the password and create a base64 encoded key
    key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
    # print(f"[DEBUG] Generated Key: {key}")  # Debug statement
    return key

# Function to encrypt a message with the generated key
def encrypt_message(message, key):
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    # print(f"[DEBUG] Encrypted Message: {encrypted_message}")  # Debug statement
    return encrypted_message

# Function to decrypt an encrypted message with the same key used for encryption
def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    # print(f"[DEBUG] Decrypted Message: {decrypted_message}")  # Debug statement
    return decrypted_message

# Function to calculate the maximum message size that can be stored in an image
def max_message_size(image_path):
    image = Image.open(image_path)
    width, height = image.size
    return (width * height * 3) // 8  # Each pixel can hold 3 bits (1 per RGB channel)

class SteganographyApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Steganography App")
        self.geometry("800x500")
        ctk.set_appearance_mode("dark")  # Set theme to dark mode
        ctk.set_default_color_theme("blue")

        # Initialize a tabbed view to separate encoding and decoding functionalities
        self.tabview = ctk.CTkTabview(self, width=750, height=450)
        self.tabview.pack(pady=10)

        # Create Encode and Decode tabs
        self.encode_tab = self.tabview.add("Encode")
        self.decode_tab = self.tabview.add("Decode")

        # Set up Encode and Decode tab layouts
        self.create_encode_tab()
        self.create_decode_tab()

    # Function to create the layout for the Encode tab
    def create_encode_tab(self):
        # Left side: Image selection and preview for encoding
        left_frame = ctk.CTkFrame(self.encode_tab, width=300, corner_radius=10)
        left_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        # Label, image preview area, and button for selecting an image
        ctk.CTkLabel(left_frame, text="Select Image to Encode", font=("Helvetica", 14, "bold")).pack(anchor="w", pady=5)
        self.image_label_encode = ctk.CTkLabel(left_frame, text="No Image Selected", width=280, height=280, fg_color=("white", "gray"))
        self.image_label_encode.pack(pady=5)
        ctk.CTkButton(left_frame, text="Open Image", command=self.select_image_encode).pack(pady=5)

        # Label to display maximum message size based on image size
        self.max_msg_size_label = ctk.CTkLabel(left_frame, text="Max message size: N/A", font=("Helvetica", 10))
        self.max_msg_size_label.pack(pady=5)

        # Right side: Message input, password input, and encode button
        right_frame = ctk.CTkFrame(self.encode_tab, width=450, corner_radius=10)
        right_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        # Input area for entering the message to encode
        ctk.CTkLabel(right_frame, text="Enter Message", font=("Helvetica", 14, "bold")).pack(anchor="w", pady=5)
        self.message_entry = ctk.CTkTextbox(right_frame, width=400, height=150)
        self.message_entry.pack(pady=5)
        self.message_entry.bind("<KeyRelease>", self.update_char_count)  # Update character count as message is typed

        # Label to show current character count for the message
        self.char_count_label = ctk.CTkLabel(right_frame, text="Characters: 0", font=("Helvetica", 10))
        self.char_count_label.pack()

        # Password input area for encrypting the message
        ctk.CTkLabel(right_frame, text="Set Password", font=("Helvetica", 14, "bold")).pack(anchor="w", pady=5)
        self.password = ctk.StringVar()
        self.password_entry = ctk.CTkEntry(right_frame, textvariable=self.password, show='*', width=400)
        self.password_entry.pack(pady=5)

        # Button to initiate the encoding process
        ctk.CTkButton(right_frame, text="Encode Message", command=self.encode_message, width=200).pack(pady=10)

        # Label to display output messages or status of encoding
        self.output_label_encode = ctk.CTkLabel(right_frame, text="", text_color="cyan", font=("Helvetica", 10))
        self.output_label_encode.pack(pady=10)

    # Function to create the layout for the Decode tab
    def create_decode_tab(self):
        # Left side: Image selection and preview for decoding
        left_frame = ctk.CTkFrame(self.decode_tab, width=300, corner_radius=10)
        left_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        # Label, image preview area, and button for selecting an image
        ctk.CTkLabel(left_frame, text="Select Image to Decode", font=("Helvetica", 14, "bold")).pack(anchor="w", pady=5)
        self.image_label_decode = ctk.CTkLabel(left_frame, text="No Image Selected", width=280, height=280, fg_color=("white", "gray"))
        self.image_label_decode.pack(pady=5)
        ctk.CTkButton(left_frame, text="Open Image", command=self.select_image_decode).pack(pady=5)

        # Right side: Password input, decode button, and output message display
        right_frame = ctk.CTkFrame(self.decode_tab, width=450, corner_radius=10)
        right_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        # Password input area for decrypting the message
        ctk.CTkLabel(right_frame, text="Enter Password", font=("Helvetica", 14, "bold")).pack(anchor="w", pady=5)
        self.password_decode = ctk.StringVar()
        self.password_entry_decode = ctk.CTkEntry(right_frame, textvariable=self.password_decode, show='*', width=400)
        self.password_entry_decode.pack(pady=5)

        # Button to initiate the decoding process
        ctk.CTkButton(right_frame, text="Decode Message", command=self.decode_message, width=200).pack(pady=10)

        # Textbox to display the decoded message; this is read-only to prevent editing
        self.output_textbox_decode = ctk.CTkTextbox(right_frame, width=400, height=150, state="disabled")
        self.output_textbox_decode.pack(pady=10)

    # Function to open a file dialog and select an image for encoding
    def select_image_encode(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg *.jpeg")])
        if file_path:
            self.image_path_encode = file_path
            img = Image.open(file_path)
            img.thumbnail((280, 280))  # Resize for preview
            img = ImageTk.PhotoImage(img)
            self.image_label_encode.configure(image=img, text="")
            self.image_label_encode.image = img
            self.max_msg_size = max_message_size(file_path)  # Calculate max message size
            self.max_msg_size_label.configure(text=f"Max message size: {self.max_msg_size} characters")

    # Function to open a file dialog and select an image for decoding
    def select_image_decode(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg *.jpeg")])
        if file_path:
            self.image_path_decode = file_path
            img = Image.open(file_path)
            img.thumbnail((280, 280))  # Resize for preview
            img = ImageTk.PhotoImage(img)
            self.image_label_decode.configure(image=img, text="")
            self.image_label_decode.image = img

    # Function to update the character count as the user types a message
    def update_char_count(self, event=None):
        char_count = len(self.message_entry.get("1.0", "end-1c"))
        self.char_count_label.configure(text=f"Characters: {char_count}")
        if char_count > self.max_msg_size:
            self.message_entry.configure(fg_color="red")  # Red text if message exceeds limit
        else:
            self.message_entry.configure(fg_color="white")  # Default color otherwise

    # Function to encode the message into the selected image
    def encode_message(self):
        if not hasattr(self, 'image_path_encode'):
            messagebox.showerror("Error", "No image selected.")
            return
        if len(self.message_entry.get("1.0", "end-1c")) > self.max_msg_size:
            messagebox.showerror("Error", "Message is too long for the selected image.")
            return
        if not self.password.get():
            messagebox.showerror("Error", "Password is required.")
            return
        
        key = generate_key(self.password.get())  # Generate encryption key
        encrypted_message = encrypt_message(self.message_entry.get("1.0", "end-1c") + '####', key)
        message_bits = ''.join(format(byte, '08b') for byte in encrypted_message)

        # Encode message bits into image pixels
        image = Image.open(self.image_path_encode).convert('RGB')
        encoded = image.copy()
        width, height = image.size
        index = 0

        for row in range(height):
            for col in range(width):
                if index < len(message_bits):
                    pixel = list(image.getpixel((col, row)))
                    for n in range(3):
                        if index < len(message_bits):
                            pixel[n] = pixel[n] & ~1 | int(message_bits[index])  # Modify LSB
                            index += 1
                    encoded.putpixel((col, row), tuple(pixel))
                else:
                    break

        # Save the encoded image
        output_path = os.path.join(os.path.dirname(self.image_path_encode), "encoded_image.png")
        encoded.save(output_path)
        self.output_label_encode.configure(text=f"Message encoded and saved as {output_path}")

    # Function to decode the message from the selected image
    def decode_message(self):
        if not hasattr(self, 'image_path_decode'):
            messagebox.showerror("Error", "No image selected.")
            return
        if not self.password_decode.get():
            messagebox.showerror("Error", "Password is required.")
            return

        key = generate_key(self.password_decode.get())  # Generate decryption key
        image = Image.open(self.image_path_decode)
        width, height = image.size
        message_bits = []

        # Extract message bits from image pixels
        for row in range(height):
            for col in range(width):
                pixel = image.getpixel((col, row))
                for n in range(3):
                    message_bits.append(pixel[n] & 1)  # Collect LSBs

        # Convert bits to bytes
        message_bytes = bytes(int(''.join(map(str, message_bits[i:i+8])), 2) for i in range(0, len(message_bits), 8))

        # Attempt to decrypt and display the decoded message
        try:
            decrypted_message = decrypt_message(message_bytes, key).rstrip('#')
            self.output_textbox_decode.configure(state="normal")
            self.output_textbox_decode.delete("1.0", "end")
            self.output_textbox_decode.insert("1.0", decrypted_message)
            self.output_textbox_decode.configure(state="disabled")
        except Exception as e:
            # print(f"[ERROR] {e}")  # Debugging line for errors
            messagebox.showerror("Error", "Failed to decode message. Check password or image.")

if __name__ == "__main__":
    app = SteganographyApp()
    app.mainloop()
