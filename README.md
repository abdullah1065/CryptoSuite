# CryptoSuite - Encryption/Decryption Tool and Hill Known-Plaintext Cracker (GUI + CLI)

This repository implements four classic cryptosystems with both **encryption** and **decryption**:

- Caesar Cipher
- Affine Cipher
- Playfair Cipher
- Hill Cipher (2x2 key matrix)

It also includes a **known-plaintext attack** for Hill Cipher (2x2).

## Project Requirements Covered
- Part 1: GUI/console interface to select cipher, operation (encrypt/decrypt), input key, and input text
- Part 2: Hill cipher known-plaintext cracker

## Files
- `cryptoSuite/cryptoSuite.py` - Cipher implementations (class-based)
- `app_gui.py` - Cross-platform Tkinter GUI
- `app_cli.py` - Console version (fallback if Tkinter is unavailable)
- `main.py` - Original demo runner (file-based)
- `sample keys/` - Sample keys
- `sample texts/` - Sample input/output text files

## Requirements
- Python 3.8+ recommended
- No external packages required for the app itself.
- The GUI uses `tkinter` (usually included with Python).

### Check Tkinter (GUI)
Run:
```bash
python -m tkinter
```
If a small window opens, Tkinter is installed.

**Windows:** The python.org installer typically includes Tkinter.  
**macOS:** The python.org installer typically includes Tkinter. Some minimal/alternate Python installs may not include it. If GUI doesn't start, use the CLI version.

## How to Run (GUI)
```bash
python app_gui.py
```

## How to Run (CLI)
```bash
python app_cli.py
```

## Key Formats
- **Caesar:** integer shift (e.g., `5`)
- **Affine:** two integers `a b` (e.g., `5 8`). Note: `gcd(a, 26) = 1`.
- **Playfair:** keyword (letters). `J` is treated as `I`.
- **Hill (2x2):** 4 integers as a 2x2 matrix, e.g.:
```text
3 3
2 5
```
Matrix must be invertible mod 26.

## Notes
- Non-letter symbols (spaces, punctuation) are preserved in the output for all ciphers.
- For Playfair, filler 'X' may be inserted during encryption (standard behavior).

## Credits
- Developed as a course project.
- Assisted by LLM applications [ChatGPT and Gemini] for refactoring and packaging guidance.
