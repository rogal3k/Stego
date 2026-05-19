import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 1. GENERATOR AES-CTR DO WYZNACZANIA INDEKSÓW I BITÓW WYBIELAJĄCYCH
class AES_CTR_PRNG:
    def __init__(self, key: bytes, nonce: bytes):
        self.cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        self.encryptor = self.cipher.encryptor()
        self.buffer = b""
        self.bit_buffer = []  # Bufor na pojedyncze bity do XORowania

    def get_random_bytes(self, num_bytes: int) -> bytes:
        while len(self.buffer) < num_bytes:
            zeros = b"\x00" * 1024
            self.buffer += self.encryptor.update(zeros)
        result = self.buffer[:num_bytes]
        self.buffer = self.buffer[num_bytes:]
        return result

    def get_random_bit(self) -> int:
        if not self.bit_buffer:
            byte = self.get_random_bytes(1)[0]
            for i in range(8):
                self.bit_buffer.append((byte >> (7 - i)) & 1)
        return self.bit_buffer.pop(0)

    def get_indices_for_block(self, num_indices: int = 2) -> list:
        indices = set()
        while len(indices) < num_indices:
            rand_byte = self.get_random_bytes(1)[0]
            index = rand_byte & 0x7F  # Maska 0-127
            indices.add(index)
        return list(indices)

# 2. FUNKCJE POMOCNICZE
def derive_key_nonce(password: str):
    key = hashlib.sha256(password.encode('utf-8')).digest()
    nonce = hashlib.sha256((password + "nonce_salt").encode('utf-8')).digest()[:16]
    return key, nonce

def bytes_to_bit_list(byte_data: bytes) -> list:
    bits = []
    for b in byte_data:
        for i in range(8):
            bits.append((b >> (7 - i)) & 1)
    return bits

def bit_list_to_bytes(bit_list: list) -> bytes:
    byte_data = bytearray()
    for i in range(0, len(bit_list), 8):
        b = 0
        for j in range(8):
            if i + j < len(bit_list):
                b |= (bit_list[i+j] << (7 - j))
        byte_data.append(b)
    return bytes(byte_data)

# 3. GŁÓWNA LOGIKA: UKRYWANIE
def embed_message(input_path: str, output_path: str, password: str, bits_per_block: int, mode: str = "WHITENING"):
    key, nonce = derive_key_nonce(password)
    prng = AES_CTR_PRNG(key, nonce)
    
    embedded_count = 0
    bytes_processed = 0
    MAX_EMBED_BYTES = int(12.8 * 1024 * 1024) # Obszar pracy
    
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        while True:
            block_bytes = f_in.read(16)
            if not block_bytes:
                break
                
            if bytes_processed < MAX_EMBED_BYTES and len(block_bytes) == 16:
                bits = bytes_to_bit_list(block_bytes)
                msg_indices = prng.get_indices_for_block(bits_per_block)
                
                for idx in msg_indices:
                    msg_bit = 1 # zawartość wiadomości - same jedynki
                    
                    if mode == "WHITENING": # XOR
                        aes_bit = prng.get_random_bit()
                        stego_bit = msg_bit ^ aes_bit
                    else:
                        stego_bit = 1 # Tryb PLAIN - brute-force jedynki
                        
                    bits[idx] = stego_bit
                        
                f_out.write(bit_list_to_bytes(bits))
                embedded_count += bits_per_block
                bytes_processed += 16
            else:
                f_out.write(block_bytes)
                
    return embedded_count

# 4. GŁÓWNA LOGIKA: EKSTRAKCJA
def extract_message(stego_path: str, password: str, bits_per_block: int, expected_bits: int, mode: str = "WHITENING"):
    key, nonce = derive_key_nonce(password)
    prng = AES_CTR_PRNG(key, nonce) 
    
    extracted_message = []
    
    with open(stego_path, 'rb') as f_in:
        while True:
            block_bytes = f_in.read(16)
            if not block_bytes:
                break
                
            if len(extracted_message) < expected_bits and len(block_bytes) == 16:
                bits = bytes_to_bit_list(block_bytes)
                msg_indices = prng.get_indices_for_block(bits_per_block)
                
                for idx in msg_indices:
                    stego_bit = bits[idx]
                    
                    if mode == "WHITENING":
                        aes_bit = prng.get_random_bit()
                        msg_bit = stego_bit ^ aes_bit
                    else:
                        msg_bit = stego_bit
                        
                    extracted_message.append(msg_bit) 
            else:
                break
                
    return extracted_message

# 5. TESTOWANIE SKRYPTU
if __name__ == "__main__":
    PLIK_ZRODLOWY = "TRNG_P.bit"   
    PLIK_STEGO = "stego6w_TRNG_P.bit"
    HASLO = "TajneHaslo123"
    BITY_NA_BLOK = 6
    
    TRYB = "WHITENING"  
    
    print("\nETAP 1: UKRYWANIE...")
    ukryte_bity = embed_message(PLIK_ZRODLOWY, PLIK_STEGO, HASLO, BITY_NA_BLOK, mode=TRYB)
    print(f"Zakończono. 'Ukryto' {ukryte_bity} jedynek w pliku.")
    
    print("\nETAP 2: EKSTRAKCJA WIADOMOŚCI...")
    odzyskana_wiadomosc = extract_message(PLIK_STEGO, HASLO, BITY_NA_BLOK, ukryte_bity, mode=TRYB)
    print(f"Odzyskano {len(odzyskana_wiadomosc)} bitów z pliku nośnika.")
    
    # WERYFIKACJA SPÓJNOŚCI DANYCH
    czy_same_jedynki = all(bit == 1 for bit in odzyskana_wiadomosc)
    
    print("\nWYNIK KOŃCOWY")
    if czy_same_jedynki and len(odzyskana_wiadomosc) == ukryte_bity:
        print("SUKCES! Odbiorca poprawnie wyodrębnił strukturę samych jedynek [1, 1, 1...].")
    else:
        print("BŁĄD! Wyciągnięte bity nie pasują do wysłanej wiadomości.")
        