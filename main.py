import hashlib
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 1. GENERATOR AES-CTR DO WYZNACZANIA INDEKSÓW
class AES_CTR_PRNG:
    def __init__(self, key: bytes, nonce: bytes):
        self.cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        self.encryptor = self.cipher.encryptor()
        self.buffer = b""

    def get_random_bytes(self, num_bytes: int) -> bytes:
        while len(self.buffer) < num_bytes:
            zeros = b"\x00" * 1024
            self.buffer += self.encryptor.update(zeros)
        result = self.buffer[:num_bytes]
        self.buffer = self.buffer[num_bytes:]
        return result

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
    # nonce_salt, aby wygenerować unikalny hash dla nonce - jakiś stały string
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
            b |= (bit_list[i+j] << (7 - j))
        byte_data.append(b)
    return bytes(byte_data)

# 3. GŁÓWNA LOGIKA: UKRYWANIE
def embed_ones(input_path: str, output_path: str, password: str, bits_per_block: int = 2):
    key, nonce = derive_key_nonce(password)
    prng = AES_CTR_PRNG(key, nonce)
    
    embedded_count = 0
    bytes_processed_for_stego = 0
    
    # Przeniesiony dług z poprzednich bloków
    global_debt = 0
    
    # 12.8 MB (12.8 * 1024 * 1024 = 13421772 bajty)
    MAX_EMBED_BYTES = int(12.8 * 1024 * 1024) 
    
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        while True:
            # Blok 16 bajtów (128 bitów)
            block_bytes = f_in.read(16)
            
            if not block_bytes:
                break
                
            # Modyfikacja tylko, jeśli nie przekroczono limitu 12.8 MB i pełen blok 16 bajtów
            if bytes_processed_for_stego < MAX_EMBED_BYTES and len(block_bytes) == 16:
                bits = bytes_to_bit_list(block_bytes)
                msg_indices = prng.get_indices_for_block(bits_per_block)
                
                # Zliczamy dług wygenerowany TYLKO w tym bloku
                local_debt = 0
                for idx in msg_indices:
                    if bits[idx] == 0:
                        bits[idx] = 1
                        local_debt += 1
                        
                # Całkowity dług do spłacenia w tym bloku to dług lokalny + dług zaległy
                total_debt = local_debt + global_debt
                
                if total_debt > 0:
                    candidates = [i for i in range(128) if i not in msg_indices and bits[i] == 1]
                    
                    if len(candidates) >= total_debt:
                        # Jesteśmy w stanie spłacić cały dług
                        comp_indices = random.sample(candidates, total_debt)
                        for idx in comp_indices:
                            bits[idx] = 0 
                        global_debt = 0  # Dług wyzerowany
                    else:
                        # Nie mamy wystarczająco dużo jedynek. Gasimy wszystkie, które możemy
                        for idx in candidates:
                            bits[idx] = 0
                        # resztę długu przepisujemy na kolejny blok
                        global_debt = total_debt - len(candidates)
                        
                f_out.write(bit_list_to_bytes(bits))
                embedded_count += bits_per_block
                bytes_processed_for_stego += 16
            else:
                f_out.write(block_bytes)
                
    total_bits_in_target_area = bytes_processed_for_stego * 8
    
    percentage = (embedded_count / total_bits_in_target_area) * 100 if total_bits_in_target_area > 0 else 0.0
        
    print(f"Zakończono modyfikację w obszarze pierwszych {bytes_processed_for_stego} bajtów.")
    print(f"Ukryto łącznie: {embedded_count} bitów (jedynek).")
    print(f"Pozostały, niespłacony dług na końcu pliku: {global_debt} bitów.")
    print(f"Wykorzystana pojemność steganograficzna obszaru testowego: {percentage:.4f}%")
    
    return embedded_count, percentage


# 4. GŁÓWNA LOGIKA: ODZYSKIWANIE
def extract_ones(stego_path: str, password: str, bits_per_block: int = 2, max_bits_to_read: int = 100):
    key, nonce = derive_key_nonce(password)
    # Inicjalizacja generatora z tymi samymi parametrami
    prng = AES_CTR_PRNG(key, nonce) 
    
    extracted = []
    
    with open(stego_path, 'rb') as f_in:
        while True:
            if len(extracted) >= max_bits_to_read:
                break
                
            block_bytes = f_in.read(16)
            if len(block_bytes) < 16:
                break
                
            bits = bytes_to_bit_list(block_bytes)
            msg_indices = prng.get_indices_for_block(bits_per_block)
            
            # Odczyt bitów z wyznaczonych indeksów
            for idx in msg_indices:
                extracted.append(bits[idx])
                
    # Zwracamy listę odzyskanych bitów
    return extracted[:max_bits_to_read]


# 5. TESTOWANIE SKRYPTU
if __name__ == "__main__":
    PLIK_ZRODLOWY = "TRNG_P.bit"   
    PLIK_STEGO = "stego44_TRNG_P.bit"
    HASLO = "TajneHaslo123"
    BITY_NA_BLOK = 44

    print("ETAP 1: UKRYWANIE")
    ukryte_bity, procent_pojemnosci = embed_ones(PLIK_ZRODLOWY, PLIK_STEGO, HASLO, BITY_NA_BLOK)
    
    print("\nETAP 2: ODZYSKIWANIE")
    odzyskana_wiadomosc = extract_ones(PLIK_STEGO, HASLO, BITY_NA_BLOK, max_bits_to_read=ukryte_bity)

    print(f"Zakończono odczyt. Pobrano {len(odzyskana_wiadomosc)} bitów.")
    
    # Dwie rzeczy do sprawdzenia: 
    # 1. Czy odzyskaliśmy dokładnie tyle bitów, ile schowaliśmy?
    # 2. Czy każdy z tych bitów to jedynka?
    if len(odzyskana_wiadomosc) == ukryte_bity and all(bit == 1 for bit in odzyskana_wiadomosc):
        print("Sukces! Odzyskano poprawnie całą wiadomość.")
    else:
        print("Błąd! Odtworzona wiadomość jest niekompletna lub zawiera błędy!")