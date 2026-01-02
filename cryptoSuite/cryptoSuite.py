from __future__ import annotations

from typing import List, Tuple, Optional


# ---------------------------------------------------------------------------
# 1) Caesar Cipher
# ---------------------------------------------------------------------------

class CaesarCipher:
    def __init__(self, key: int = 3) -> None:
        self.key = key

    def encrypt(self, plain_text: str) -> str:
        plain_text = plain_text.lower()
        result_chars: List[str] = []

        for ch in plain_text:
            if ch.isalpha():
                # Convert 'a'..'z' -> 0..25
                x = ord(ch) - ord('a')

                # Shift by key with wrap-around
                y = (x + self.key) % 26

                # Convert back to letter and output as uppercase
                out_ch = chr(y + ord('A'))
                result_chars.append(out_ch)
            else:
                result_chars.append(ch)

        return "".join(result_chars)

    def decrypt(self, cipher_text: str) -> str:
        cipher_text = cipher_text.upper()
        result_chars: List[str] = []

        for ch in cipher_text:
            if ch.isalpha():
                # Convert 'A'..'Z' -> 0..25
                x = ord(ch) - ord('A')

                # Reverse shift by key
                y = (x - self.key) % 26

                # Convert back and output as lowercase
                out_ch = chr(y + ord('a'))
                result_chars.append(out_ch)
            else:
                result_chars.append(ch)

        return "".join(result_chars)


# ---------------------------------------------------------------------------
# 2) Affine Cipher
# ---------------------------------------------------------------------------

class AffineCipher:
    def __init__(self, key: Tuple[int, int] = (9, 2)) -> None:
        self.key = key

    def _a_inv(self) -> int:
        a = self.key[0]
        return pow(a, -1, 26)

    def encrypt(self, plain_text: str) -> str:
        plain_text = plain_text.lower()
        a, b = self.key
        result_chars: List[str] = []

        for ch in plain_text:
            if ch.isalpha():
                x = ord(ch) - ord('a')
                y = (a * x + b) % 26
                out_ch = chr(y + ord('A'))
                result_chars.append(out_ch)
            else:
                result_chars.append(ch)

        return "".join(result_chars)

    def decrypt(self, cipher_text: str) -> str:
        cipher_text = cipher_text.upper()
        a, b = self.key
        a_inv = self._a_inv()
        result_chars: List[str] = []

        for ch in cipher_text:
            if ch.isalpha():
                x = ord(ch) - ord('A')
                # Reverse affine: a_inv * (x - b)
                y = (a_inv * (x - b)) % 26
                out_ch = chr(y + ord('a'))
                result_chars.append(out_ch)
            else:
                result_chars.append(ch)

        return "".join(result_chars)


# ---------------------------------------------------------------------------
# 3) Playfair Cipher
# ---------------------------------------------------------------------------

class PlayfairCipher:
    def __init__(self, key: str = "MONARCHY") -> None:
        self.keymatrix: Tuple[Tuple[str, ...], ...] = self.__create_keymatrix(key)

    # ----- Key matrix creation helpers -----

    def __create_keymatrix(self, key: str) -> Tuple[Tuple[str, ...], ...]:
        key = key.upper()

        # Remove duplicates while preserving order
        seen = set()
        unique_chars: List[str] = []
        for ch in key:
            if ch.isalpha() and ch not in seen:
                seen.add(ch)
                unique_chars.append(ch)

        # Append remaining letters
        for code in range(ord('A'), ord('Z') + 1):
            ch = chr(code)
            if ch not in seen:
                seen.add(ch)
                unique_chars.append(ch)

        # Remove J (I/J combined)
        if 'J' in unique_chars:
            unique_chars.remove('J')

        # Now we must have 25 letters
        # Build 5x5 matrix
        matrix: List[Tuple[str, ...]] = []
        for i in range(0, 25, 5):
            matrix.append(tuple(unique_chars[i:i + 5]))

        return tuple(matrix)

    # ----- Text preprocessing helpers -----

    def __create_digrams(self, text: str) -> List[str]:
        digrams: List[str] = []
        i = 0

        while i < len(text):
            first = text[i]

            # second is next character or X if none left
            second = text[i + 1] if (i + 1) < len(text) else "X"

            if first == second:
                # Duplicate letter -> insert X
                digrams.append(first + "X")
                i += 1
            else:
                digrams.append(first + second)
                i += 2

        return digrams

    def __find_position(self, ch: str) -> Tuple[int, int]:
        for r in range(5):
            for c in range(5):
                if self.keymatrix[r][c] == ch:
                    return (r, c)
        raise ValueError(f"Character {ch} not found in key matrix.")

    def __remove_inserted_x(self, chars: List[str]) -> None:
        i = 1
        while i < len(chars) - 1:
            if chars[i] == "X" and chars[i - 1] == chars[i + 1]:
                del chars[i]
            else:
                i += 1

    # ----- Public encrypt/decrypt -----

    def encrypt(self, plain_text: str) -> str:
        # 1) Save non-letter symbols with their indices
        symbols: List[Tuple[int, str]] = []
        for i, ch in enumerate(plain_text):
            if not ch.isalpha():
                symbols.append((i, ch))

        # 2) Keep only letters
        letters_only = []
        for ch in plain_text:
            if ch.isalpha():
                letters_only.append(ch)

        cleaned = "".join(letters_only).upper().replace("J", "I")

        # 3) Digram creation
        digrams = self.__create_digrams(cleaned)

        # 4) Encrypt digrams
        cipher_chars: List[str] = []
        for dg in digrams:
            first, second = dg[0], dg[1]

            r1, c1 = self.__find_position(first)
            r2, c2 = self.__find_position(second)

            if r1 == r2:
                # Same row: shift LEFT (c-1) in your original code
                cipher_chars.append(self.keymatrix[r1][(c1 - 1) % 5])
                cipher_chars.append(self.keymatrix[r2][(c2 - 1) % 5])

            elif c1 == c2:
                # Same column: shift UP (r-1) in your original code
                cipher_chars.append(self.keymatrix[(r1 - 1) % 5][c1])
                cipher_chars.append(self.keymatrix[(r2 - 1) % 5][c2])

            else:
                # Rectangle: swap columns
                cipher_chars.append(self.keymatrix[r1][c2])
                cipher_chars.append(self.keymatrix[r2][c1])

        # 5) Reinsert symbols
        for pos, sym in symbols:
            cipher_chars.insert(pos, sym)

        return "".join(cipher_chars)

    def decrypt(self, cipher_text: str) -> str:
        # 1) Save non-letter symbols
        symbols: List[Tuple[int, str]] = []
        for i, ch in enumerate(cipher_text):
            if not ch.isalpha():
                symbols.append((i, ch))

        # Remove non-letters
        letters_only = []
        for ch in cipher_text:
            if ch.isalpha():
                letters_only.append(ch)

        cleaned = "".join(letters_only).upper().replace("J", "I")

        # 3) Split into digrams
        digrams = []
        for i in range(0, len(cleaned), 2):
            digrams.append(cleaned[i:i + 2])

        # 4) Decrypt digrams
        plain_chars: List[str] = []
        for dg in digrams:
            first, second = dg[0], dg[1]

            r1, c1 = self.__find_position(first)
            r2, c2 = self.__find_position(second)

            if r1 == r2:
                # Same row: shift RIGHT (c+1) in your original code
                plain_chars.append(self.keymatrix[r1][(c1 + 1) % 5])
                plain_chars.append(self.keymatrix[r2][(c2 + 1) % 5])

            elif c1 == c2:
                # Same column: shift DOWN (r+1) in your original code
                plain_chars.append(self.keymatrix[(r1 + 1) % 5][c1])
                plain_chars.append(self.keymatrix[(r2 + 1) % 5][c2])

            else:
                # Rectangle: swap columns
                plain_chars.append(self.keymatrix[r1][c2])
                plain_chars.append(self.keymatrix[r2][c1])

        # 5) Reinsert symbols
        for pos, sym in symbols:
            plain_chars.insert(pos, sym)

        # 6) Remove inserted X's
        self.__remove_inserted_x(plain_chars)

        return "".join(plain_chars).lower()


# ---------------------------------------------------------------------------
# 4) Hill Cipher (2x2)
# ---------------------------------------------------------------------------

class HillCipher:
    def __init__(self, key: List[List[int]] = [[5, 8], [17, 13]]) -> None:
        self.key = key

    # ----- Encoding helpers -----

    def __to_numbers(self, text: str) -> List[int]:
        nums: List[int] = []
        for ch in text:
            nums.append(ord(ch) - ord('A'))
        return nums

    def __to_letters(self, nums: List[int]) -> List[str]:
        letters: List[str] = []
        for n in nums:
            letters.append(chr(n + ord('A')))
        return letters

    # ----- Modular arithmetic helpers -----

    def __mod_product(self, A: List[List[int]], v: List[int]) -> List[int]:
        v0, v1 = v[0], v[1]

        u0 = (v0 * A[0][0] + v1 * A[1][0]) % 26
        u1 = (v0 * A[0][1] + v1 * A[1][1]) % 26

        return [u0, u1]

    def __mod_matmul(self, A: List[List[int]], B: List[List[int]]) -> List[List[int]]:
        return [
            [
                (A[0][0] * B[0][0] + A[0][1] * B[1][0]) % 26,
                (A[0][0] * B[0][1] + A[0][1] * B[1][1]) % 26,
            ],
            [
                (A[1][0] * B[0][0] + A[1][1] * B[1][0]) % 26,
                (A[1][0] * B[0][1] + A[1][1] * B[1][1]) % 26,
            ],
        ]

    def __inverse_mat(self, mat: List[List[int]]) -> List[List[int]]:
        a, b = mat[0][0], mat[0][1]
        c, d = mat[1][0], mat[1][1]

        det = (a * d - b * c) % 26
        det_inv = pow(det, -1, 26)  # ValueError if not invertible

        inv = [
            [(d * det_inv) % 26, (-b * det_inv) % 26],
            [(-c * det_inv) % 26, (a * det_inv) % 26],
        ]
        return inv

    # ----- Cracking helpers -----

    def __try_crack(self, plain_mat: List[List[int]], cipher_mat: List[List[int]]) -> Optional[List[List[int]]]:
        try:
            plain_inv = self.__inverse_mat(plain_mat)
            key = self.__mod_matmul(plain_inv, cipher_mat)
            return key
        except Exception:
            return None

    # ----- Public encrypt/decrypt -----

    def encrypt(self, plain_text: str) -> str:
        # 1) Save non-letter symbols
        symbols: List[Tuple[int, str]] = []
        for i, ch in enumerate(plain_text):
            if not ch.isalpha():
                symbols.append((i, ch))

        # 2) Keep only letters and uppercase
        letters = []
        for ch in plain_text:
            if ch.isalpha():
                letters.append(ch)
        cleaned = "".join(letters).upper()

        # 3) Convert to numbers
        plain_nums = self.__to_numbers(cleaned)

        # 4) Pad if needed
        if len(plain_nums) % 2 == 1:
            plain_nums.append(23)  # X

        # 5) Encrypt in blocks
        cipher_nums: List[int] = []
        for i in range(0, len(plain_nums), 2):
            block = [plain_nums[i], plain_nums[i + 1]]
            out_block = self.__mod_product(self.key, block)
            cipher_nums.extend(out_block)

        # 6) Convert back and reinsert symbols
        cipher_letters = self.__to_letters(cipher_nums)
        for pos, sym in symbols:
            cipher_letters.insert(pos, sym)

        return "".join(cipher_letters)

    def decrypt(self, cipher_text: str) -> str:
        key_inv = self.__inverse_mat(self.key)

        # 2) Save non-letter symbols
        symbols: List[Tuple[int, str]] = []
        for i, ch in enumerate(cipher_text):
            if not ch.isalpha():
                symbols.append((i, ch))

        # 3) Keep only letters and uppercase
        letters = []
        for ch in cipher_text:
            if ch.isalpha():
                letters.append(ch)
        cleaned = "".join(letters).upper()

        # 4) Convert to numbers
        cipher_nums = self.__to_numbers(cleaned)

        # 5) Decrypt blocks
        plain_nums: List[int] = []
        for i in range(0, len(cipher_nums), 2):
            block = [cipher_nums[i], cipher_nums[i + 1]]
            out_block = self.__mod_product(key_inv, block)
            plain_nums.extend(out_block)

        # 6) Convert back and reinsert symbols
        plain_letters = self.__to_letters(plain_nums)
        for pos, sym in symbols:
            plain_letters.insert(pos, sym)

        return "".join(plain_letters).lower()

    def crack_key(self, plain_text: str, cipher_text: str) -> Optional[List[List[int]]]:
        # Keep only letters and uppercase
        p_letters = [ch for ch in plain_text if ch.isalpha()]
        c_letters = [ch for ch in cipher_text if ch.isalpha()]

        p_clean = "".join(p_letters).upper()
        c_clean = "".join(c_letters).upper()

        p_nums = self.__to_numbers(p_clean)
        c_nums = self.__to_numbers(c_clean)

        # Need at least 4 letters (2 blocks)
        if len(p_nums) < 4 or len(c_nums) < 4:
            return None

        key: Optional[List[List[int]]] = None

        # Slide by 2 (block size) to keep alignment
        for i in range(0, len(p_nums) - 3, 2):
            plain_mat = [
                [p_nums[i],     p_nums[i + 1]],
                [p_nums[i + 2], p_nums[i + 3]],
            ]
            cipher_mat = [
                [c_nums[i],     c_nums[i + 1]],
                [c_nums[i + 2], c_nums[i + 3]],
            ]

            key_try = self.__try_crack(plain_mat, cipher_mat)
            if key_try is not None:
                key = key_try
                break

        return key
