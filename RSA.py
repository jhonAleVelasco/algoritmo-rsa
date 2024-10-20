import tkinter as tk
from tkinter import messagebox, ttk
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import base64  # Para codificar/decodificar el texto cifrado

# Funciones de criptografía
def generate_rsa_keys():
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key
    except Exception as e:
        messagebox.showerror("Error", f"Error al generar claves: {str(e)}")

def encrypt_message(public_key, message):
    try:
        ciphertext = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode('utf-8')  # Codificar a base64
    except Exception as e:
        messagebox.showerror("Error", f"Error al cifrar mensaje: {str(e)}")

def decrypt_message(private_key, ciphertext):
    try:
        ciphertext = base64.b64decode(ciphertext)  # Decodificar desde base64
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()
    except Exception as e:
        messagebox.showerror("Error", f"Error al descifrar mensaje: {str(e)}")

# Funciones de la interfaz
def generar_claves():
    global private_key, public_key
    private_key, public_key = generate_rsa_keys()
    messagebox.showinfo("Éxito", "Claves RSA generadas correctamente")

def cifrar_mensaje():
    if not public_key:
        messagebox.showerror("Error", "Primero genera las claves.")
        return
    message = entry_message.get()
    if not message:
        messagebox.showerror("Error", "El campo de mensaje está vacío.")
        return
    ciphertext = encrypt_message(public_key, message)
    if ciphertext:
        entry_ciphertext.delete(1.0, tk.END)
        entry_ciphertext.insert(tk.END, ciphertext)

def descifrar_mensaje():
    if not private_key:
        messagebox.showerror("Error", "Primero genera las claves.")
        return
    ciphertext = entry_ciphertext.get(1.0, tk.END).strip()  # Eliminar espacios en blanco
    if not ciphertext:
        messagebox.showerror("Error", "No hay texto cifrado.")
        return
    decrypted_message = decrypt_message(private_key, ciphertext)
    if decrypted_message:
        entry_decrypted.delete(1.0, tk.END)
        entry_decrypted.insert(tk.END, decrypted_message)

# Crear la ventana principal
root = tk.Tk()
root.title("Cifrado RSA")
root.geometry("500x400")
root.configure(bg="#f0f0f0")  # Color de fondo

# Claves RSA
private_key = None
public_key = None

# Etiquetas y campos de entrada
label_message = ttk.Label(root, text="Mensaje", background="#f0f0f0")
label_message.pack(pady=5)
entry_message = ttk.Entry(root, width=50)
entry_message.pack(pady=5)

button_generate = ttk.Button(root, text="Generar Claves", command=generar_claves)
button_generate.pack(pady=10)

button_encrypt = ttk.Button(root, text="Cifrar Mensaje", command=cifrar_mensaje)
button_encrypt.pack(pady=10)

label_ciphertext = ttk.Label(root, text="Mensaje Cifrado", background="#f0f0f0")
label_ciphertext.pack(pady=5)
entry_ciphertext = tk.Text(root, height=5, width=50)
entry_ciphertext.pack(pady=5)

button_decrypt = ttk.Button(root, text="Descifrar Mensaje", command=descifrar_mensaje)
button_decrypt.pack(pady=10)

label_decrypted = ttk.Label(root, text="Mensaje Descifrado", background="#f0f0f0")
label_decrypted.pack(pady=5)
entry_decrypted = tk.Text(root, height=5, width=50)
entry_decrypted.pack(pady=5)

# Ejecutar la ventana principal
root.mainloop()