from cryptoSuite.cryptoSuite import CaesarCipher, AffineCipher, PlayfairCipher, HillCipher

# Caesar ciphertext tests-----------------------------------------------------------------------
key_caesar = int(open("sample keys/caesar_key.txt", 'r').readline())

crypt_caesar = CaesarCipher(key_caesar)

plaintext_caesar = open("sample texts/plaintext.txt", 'r').readline()

open("sample texts/ciphertext_caesar.txt", 'w').write(crypt_caesar.encrypt(plaintext_caesar))

ciphertext_caesar = open("sample texts/ciphertext_caesar.txt", 'r').read()

open("sample texts/plaintext_caesar.txt", 'w').write(crypt_caesar.decrypt(ciphertext_caesar))

# Affine ciphertext tests-----------------------------------------------------------------------
key_affine = tuple(map(int, open("sample keys/affine_key.txt", 'r').readline().split()))

crypt_affine = AffineCipher(key_affine)

plaintext_affine = open("sample texts/plaintext.txt", 'r').read()

open("sample texts/ciphertext_affine.txt", 'w').write(crypt_affine.encrypt(plaintext_affine))

ciphertext_affine = open("sample texts/ciphertext_affine.txt", 'r').read()

open("sample texts/plaintext_affine.txt", 'w').write(crypt_affine.decrypt(ciphertext_affine))


# Playfair ciphertext tests-----------------------------------------------------------------------
key_playfair = open("sample keys/playfair_key.txt", 'r').readline().strip()

crypt_playfair = PlayfairCipher(key_playfair)

plaintext_playfair = open("sample texts/plaintext.txt", 'r').read()

open("sample texts/ciphertext_playfair.txt", 'w').write(crypt_playfair.encrypt(plaintext_playfair))

ciphertext_playfair = open("sample texts/ciphertext_playfair.txt", 'r').read()

open("sample texts/plaintext_playfair.txt", 'w').write(crypt_playfair.decrypt(ciphertext_playfair))


# Hill ciphertext tests----------------------------------------------------------------------------------------------
key_hill = [list(map(int, line.split())) for line in open("sample keys/hill_key.txt", 'r').read().split('\n')]

crypt_hill = HillCipher(key_hill)

plaintext_hill = open("sample texts/plaintext.txt", 'r').read()

open("sample texts/ciphertext_hill.txt", 'w').write(crypt_hill.encrypt(plaintext_hill))

ciphertext_hill = open("sample texts/ciphertext_hill.txt", 'r').read()

open("sample texts/plaintext_hill.txt", 'w').write(crypt_hill.decrypt(ciphertext_hill))

# Hill Cipher Key Cracking Tests-------------------------------------------------------------------------------------------------------------------------
open("sample texts/hill_key_cracked.txt", "w").write("\n".join(" ".join(map(str, row)) for row in crypt_hill.crack_key(plaintext_hill, ciphertext_hill)))