import struct
from Crypto.Cipher import Blowfish
from tkinter import filedialog, Tk, Button, Label, messagebox

# Keys and constants
K1, K2, K3 = 0x0153127aac36b912, 0x9fd483636609437e, 0x72723839563e6167
KEY = struct.pack('<QQQ', K1, K2, K3)
ROLLING_INIT = 0xD971
BLOCK_SIZE = 0x1050  # Encrypted size
DATA_LEN = 0x104C    # After decryption (without checksum)

def swap_endian(data):
    return b''.join([data[i:i+4][::-1] for i in range(0, len(data), 4)])

def decrypt(encrypted_data):
    to_decrypt = swap_endian(encrypted_data[:BLOCK_SIZE])
    cipher = Blowfish.new(KEY, Blowfish.MODE_ECB)
    decrypted_raw = cipher.decrypt(to_decrypt)
    block_data = swap_endian(decrypted_raw)

    # Rolling Checksum for Decryption
    state = ROLLING_INIT
    calculated_sum = 0
    for i in range(DATA_LEN):
        cipher_byte = block_data[i]
        plain_byte = ((state >> 8) ^ cipher_byte) & 0xFF
        calculated_sum = (calculated_sum + plain_byte) & 0xFFFFFFFF
        state = ((state & 0xFFFF) + plain_byte) * 0xCE6D + 0x58BF
        state &= 0xFFFF

    stored_sum = struct.unpack('<I', block_data[DATA_LEN:BLOCK_SIZE])[0]
    return block_data[:DATA_LEN], calculated_sum, stored_sum

def encrypt(plain_data):
    state = ROLLING_INIT
    calculated_sum = 0
    for byte in plain_data:
        xor_byte = ((state >> 8) ^ byte) & 0xFF
        calculated_sum = (calculated_sum + xor_byte) & 0xFFFFFFFF
        state = ((state & 0xFFFF) + xor_byte) * 0xCE6D + 0x58BF
        state &= 0xFFFF

    full_block = plain_data + struct.pack('<I', calculated_sum)
    to_encrypt = swap_endian(full_block)
    cipher = Blowfish.new(KEY, Blowfish.MODE_ECB)
    encrypted_raw = cipher.encrypt(to_encrypt)
    return swap_endian(encrypted_raw), calculated_sum

def decrypt_save():
    path = filedialog.askopenfilename(title="Select Encrypted Save")
    if not path:
        return
    with open(path, "rb") as f:
        data, calc, stored = decrypt(f.read())

    if calc == stored:
        messagebox.showinfo("Success", f"Decrypted successfully!\nChecksum: {calc:08X}")
    else:
        messagebox.showwarning("Warning", f"Checksum mismatch!\nCalculated: {calc:08X}\nStored: {stored:08X}")
    
    with open(path + '.dec', "wb") as f:
        f.write(data)

def encrypt_save():
    path = filedialog.askopenfilename(title="Select Decrypted File")
    if not path:
        return
    with open(path, "rb") as f:
        data, calc = encrypt(f.read())
    with open(path+ '.enc', "wb") as f:
        f.write(data)
    messagebox.showinfo("Success", f"Encrypted successfully!\nChecksum: {calc:08X}")

if __name__ == "__main__":
    root = Tk()
    root.title("Castle Save Tool")
    root.geometry("300x150")

    Label(root, text="Castle Save Tool", font=("Arial", 14)).pack(pady=10)
    Button(root, text="Decrypt Save", width=20, command=decrypt_save).pack(pady=5)
    Button(root, text="Encrypt Save", width=20, command=encrypt_save).pack(pady=5)

    root.mainloop()