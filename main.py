from tkinter import *
from tkinter import messagebox
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_encrypt():
    title = secret_title_entry.get()
    message = my_secret.get("1.0", END)
    key = master_key_entry.get()

    if len(title) == 0 or len(message) == 0 or len(key) == 0:
        message = messagebox.showinfo("Error!", "Please make sure of encrypted info!")
    else:
        message_encrypted = encode(key, message)
        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}\n")
        except FileNotFoundError:
            with open("mysecret.txt", "w") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}\n")
        finally:
            secret_title_entry.delete(0, END)
            my_secret.delete("1.0", END)
            master_key_entry.delete(0, END)


def decrypt():
    message_encrypted = my_secret.get("1.0", END)
    key = master_key_entry.get()

    if len(message_encrypted) == 0 or len(key) == 0:
        messagebox.showinfo("Error!", "Please enter all info!")
    else:
        try:
            decrypted_message = decode(key, message_encrypted)
            my_secret.delete("1.0", END)
            my_secret.insert("1.0", decrypted_message)  # olan mesajı silip yenisini yazdırmak.
        except:
            messagebox.showinfo("Error!", "Please enter encrypted text!")


# UI
FONT = ("Times New Roman", 13, "normal")
window = Tk()
window.title("Secret Nodes")
window.config(padx=70, pady=70)

photo = PhotoImage(file="secret.png")
photo_label = Label(image=photo)
photo_label.pack(padx=20, pady=20)

secret_title = Label(text="Enter your title", font=FONT)
secret_title.config(padx=10, pady=10)
secret_title.pack()

secret_title_entry = Entry(width=30)
secret_title_entry.pack()

secret_message = Label(text="Enter your secret", font=FONT)
secret_message.config(padx=10, pady=10)
secret_message.pack()

my_secret = Text(width=30, height=15)
my_secret.pack()

master_key = Label(text="Enter your master key", font=FONT)
master_key.config(padx=10, pady=10)
master_key.pack()

master_key_entry = Entry(width=30)
master_key_entry.pack()

encrypt_botton = Button(text="Save & Encrypt", command=save_encrypt)
encrypt_botton.pack()

decrypt_botton = Button(text="Decrypt", command=decrypt)
decrypt_botton.pack()

window.mainloop()