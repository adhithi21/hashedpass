import hashlib
import itertools
import tkinter as tk
from tkinter import ttk
from multiprocessing import Pool, cpu_count

# Function to generate the hash of a given string using the selected hash type
def generate_hash(hash_type, s):
    if hash_type == 'MD5':
        return hashlib.md5(s.encode()).hexdigest()
    elif hash_type == 'SHA-1':
        return hashlib.sha1(s.encode()).hexdigest()
    elif hash_type == 'SHA-256':
        return hashlib.sha256(s.encode()).hexdigest()
    elif hash_type == 'SHA-512':
        return hashlib.sha512(s.encode()).hexdigest()
    elif hash_type == 'SHA-3-256':
        return hashlib.sha3_256(s.encode()).hexdigest()
    elif hash_type == 'SHA-3-512':
        return hashlib.sha3_512(s.encode()).hexdigest()
    # Add other hash types here if needed
    else:
        raise ValueError("Unsupported hash type")

# Function to attempt to crack the hash
def attempt_crack(args):
    target_hash, char_set, length, hash_type = args
    for idx, word in enumerate(itertools.product(char_set, repeat=length), start=1):
        word = ''.join(word)
        print(f"Trying iteration {idx}: {word}")
        if generate_hash(hash_type, word) == target_hash:
            return word
    return None

# GUI Class
class HashCrackerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Hash Cracker")

        self.label1 = tk.Label(root, text="Enter the hash:")
        self.label1.pack()

        self.hash_entry = tk.Entry(root, width=50)
        self.hash_entry.pack()

        self.label2 = tk.Label(root, text="Select character set:")
        self.label2.pack()

        self.charsets = {
            "Lowercase": "abcdefghijklmnopqrstuvwxyz",
            "Uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "Digits": "0123456789",
            "Lowercase + Digits": "abcdefghijklmnopqrstuvwxyz0123456789",
            "Uppercase + Digits": "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "Lowercase + Uppercase": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "Lowercase + Uppercase + Digits": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "Special Characters": "!@#$%^&*()",
            "Lowercase + Special Characters": "abcdefghijklmnopqrstuvwxyz!@#$%^&*()",
            "Uppercase + Special Characters": "ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()",
            "Digits + Special Characters": "0123456789!@#$%^&*()",
            "Lowercase + Uppercase + Special Characters": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()",
            "Lowercase + Digits + Special Characters": "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()",
            "Uppercase + Digits + Special Characters": "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()",
            "All Characters": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
        }

        self.charset_combobox = ttk.Combobox(root, values=list(self.charsets.keys()))
        self.charset_combobox.current(0)
        self.charset_combobox.pack()

        self.label3 = tk.Label(root, text="Select hash type:")
        self.label3.pack()

        self.hash_types = ['MD5', 'SHA-1', 'SHA-256', 'SHA-512', 'SHA-3-256', 'SHA-3-512']  # Add other hash types here if needed
        self.hash_type_combobox = ttk.Combobox(root, values=self.hash_types)
        self.hash_type_combobox.current(0)
        self.hash_type_combobox.pack()

        self.label4 = tk.Label(root, text="Enter maximum password length:")
        self.label4.pack()

        self.length_entry = tk.Entry(root, width=5)
        self.length_entry.pack()

        self.crack_button = tk.Button(root, text="Crack Hash", command=self.crack_hash)
        self.crack_button.pack()

        self.result_label = tk.Label(root, text="")
        self.result_label.pack()

    def crack_hash(self):
        target_hash = self.hash_entry.get()
        char_set = self.charsets[self.charset_combobox.get()]
        max_length = int(self.length_entry.get())
        hash_type = self.hash_type_combobox.get()

        self.result_label.config(text="Trying to crack hash...")

        pool = Pool(processes=cpu_count())
        for length in range(1, max_length + 1):
            args = (target_hash, char_set, length, hash_type)
            result = pool.apply_async(attempt_crack, (args,))
            cracked_password = result.get()
            if cracked_password:
                self.result_label.config(text=f"Cracked! Password: {cracked_password}")
                pool.terminate()
                return

        self.result_label.config(text="Failed to crack the hash.")

# Running the GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = HashCrackerGUI(root)
    root.mainloop()
