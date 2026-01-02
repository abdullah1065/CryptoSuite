"""
Console interface for the CryptoSuite.
Fallback if Tkinter GUI isn't available.
"""

from cryptoSuite.cryptoSuite import CaesarCipher, AffineCipher, PlayfairCipher, HillCipher

def parse_affine(s: str):
    parts = [p for p in s.replace(",", " ").split() if p.strip()]
    if len(parts) != 2:
        raise ValueError("Affine key must have two integers: a b")
    return (int(parts[0]), int(parts[1]))

def parse_hill(s: str):
    nums = list(map(int, __import__("re").findall(r"-?\d+", s)))
    if len(nums) != 4:
        raise ValueError("Hill key must contain exactly 4 integers (2x2 matrix).")
    key = [[nums[0], nums[1]], [nums[2], nums[3]]]
    # Validate invertibility mod 26 (inverse exists if det has inverse mod 26)
    det = (key[0][0]*key[1][1] - key[0][1]*key[1][0]) % 26
    _ = pow(det, -1, 26)  # raises ValueError if not invertible
    return key

def get_cipher(name: str, key_text: str):
    name = name.lower()
    if name == "caesar":
        return CaesarCipher(int(key_text))
    if name == "affine":
        return AffineCipher(parse_affine(key_text))
    if name == "playfair":
        return PlayfairCipher(key_text.strip())
    if name == "hill":
        return HillCipher(parse_hill(key_text))
    raise ValueError("Unknown cipher")

def main():
    print("CryptoSuite")
    print("Ciphers: caesar, affine, playfair, hill")
    while True:
        cipher = input("\nCipher (or 'q' to quit): ").strip()
        if cipher.lower() in ("q", "quit", "exit"):
            return
        mode = input("Operation: encrypt / decrypt / crack(hill): ").strip().lower()
        if mode.startswith("crack"):
            plain = input("Known plaintext: ")
            ciph = input("Known ciphertext: ")
            key = HillCipher().crack_key(plain, ciph)
            print("Recovered Hill key (2x2):", key)
            continue

        key_text = input("Key: ")
        text = input("Text: ")

        c = get_cipher(cipher, key_text)
        if mode == "encrypt":
            print("Output:", c.encrypt(text))
        elif mode == "decrypt":
            print("Output:", c.decrypt(text))
        else:
            print("Unknown operation.")

if __name__ == "__main__":
    main()
