<p align="center">
  <img src="assets/Github-banner.png" alt="dev-lab banner" width="100%" style="max-width: 800px;">
</p>

---

## 📑 Table of Contents

- [CLI BruteForce](#cli-bruteforce)
  - [🎯 Project Goal](#-project-goal)
  - [📸 Screenshots](#-screenshots)
  - [Features](#features)
  - [Supported Formats](#supported-formats)
  - [Installation](#installation)
  - [Attack Modes](#attack-modes)
  - [Password Mangling Levels (`--mangling`)](#password-mangling-levels---mangling)
    - [Explicit Target Type (`-t`, `--type`)](#explicit-target-type--t---type)
  - [💡 Smart Features \& File Structure](#-smart-features--file-structure)
    - [📂 Automatic Output Generation](#-automatic-output-generation)
    - [⚡ Automatic Path Resolution (`data/` folder)](#-automatic-path-resolution-data-folder)
  - [Examples](#examples)
    - [1. String Target (Auto-detect length)](#1-string-target-auto-detect-length)
    - [2. File Target (Path)](#2-file-target-path)
  - [Configuration \& Defaults](#configuration--defaults)
  - [CLI Options Reference](#cli-options-reference)
  - [License](#license)

---

# CLI BruteForce

A fast, modular, and high-performance CLI password cracking and auditing utility built in Python. Designed with multi-processing support, lazy dependency loading, and cross-platform compatibility.

---

## 🎯 Project Goal

This project was built as a learning exercise to practice real-world
Python patterns: CLI design with argparse, parallel processing with
multiprocessing, modular architecture, lazy dependency loading, and
automated testing with pytest, etc.

It is not intended to compete with dedicated, GPU-accelerated tools like
Hashcat, John the Ripper, or Aircrack-ng — those solve password recovery
at a scale and speed this project doesn't aim for. The focus here is on
clean, tested, maintainable code rather than raw cracking throughput.

---

## 📸 Screenshots

<details>
<summary><b>Click to expand screenshots gallery</b></summary>
<br>

<p align="center">
  <img src="assets/Screenshot 2026-10-11 155641.png" alt="Pure Brute-Force 10 Digits" width="100%" style="max-width: 750px;">
</p>
<p align="center">
  <img src="assets/Screenshot 2026-10-11 161112.png" alt="Mangled Dictionary Search" width="100%" style="max-width: 750px;">
</p>
<p align="center">
  <img src="assets/Screenshot 2026-10-11 161906.png" alt="Full Charset Brute-Force" width="100%" style="max-width: 750px;">
</p>
<p align="center">
  <img src="assets/Screenshot 2026-10-11 162158.png" alt="Complex Charset Speed Test" width="100%" style="max-width: 750px;">
</p>
<p align="center">
  <img src="assets/Screenshot 2026-10-11 164634.png" alt="Cracking Encrypted Archives" width="100%" style="max-width: 750px;">
</p>
<p align="center">
  <img src="assets/Screenshot 2026-10-11 165029.png" alt="python main.py -h" width="100%" style="max-width: 750px;">
</p>

</details>

---

## Features

- **High Performance**: Leverages Python's `multiprocessing` to fully utilize all available CPU cores for parallel brute-force and dictionary attacks.
- **Modular Architecture**: Uses lazy dependency loading. You only need to install requirements for the specific target formats you are working with.
- **Cross-Platform**: Tested and working on Windows, Linux, and macOS.
- **Smart Binary Resolution**: Automatically detects and caches system `unrar` binaries for efficient RAR archive handling.
- **Flexible Attack Modes**: Supports brute-force enumeration, dictionary-based attacks, and rule-based password mangling levels.

---

## Supported Formats

| Target Type | Format / Extension | Required Library / Tool |
| :--- | :--- | :--- |
| **String** | Raw text comparison | Built-in |
| **ZIP** | `.zip` (AES/Standard) | `pyzipper` |
| **7z** | `.7z` | `py7zr` |
| **RAR** | `.rar` (RAR3/RAR5) | `rarfile` + system `unrar` binary |
| **PDF** | `.pdf` | `pypdf` |
| **Office** | `.docx`, `.doc`, `.xlsx`, `.xls`, `.pptx`, `.ppt` | `msoffcrypto-tool` |

---

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/MeksRa/brute-force-cli.git
   cd brute-force-cli
   ```

2. **Create and activate a virtual environment:**

   ```bash
   python -m venv .venv
   # On Windows:
   .venv\Scripts\activate
   # On Linux/macOS:
   source .venv/bin/activate
   ```

3. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

   > **Note for RAR targets:** Make sure the `unrar` utility is installed on your system and accessible via `PATH` (or located in standard installation directories like `C:\Program Files\WinRAR\UnRAR.exe` or `/usr/bin/unrar`).

---

## Attack Modes

The tool supports 3 different attack modes (`-m`, `--mode`):

1. **`hybrid` (Default)** — Combines dictionary words with character generation and mutation strategies for wider coverage.
2. **`dictionary_only`** — Performs a pure dictionary attack, checking only the passwords listed in the specified wordlist file.
3. **`bruteforce_only`** — Performs a pure brute-force enumeration based strictly on length and character sets, without using wordlists.

---

## Password Mangling Levels (`--mangling`)

Mangling rules mutate words from your wordlist to generate smart variations (useful for dictionary and hybrid attacks). Available levels:

Basic case variations (as-is, LOWERCASE, UPPERCASE, Capitalized) for levels 1-5.

- **Level 0 (Default):** Disabled. Words from the dictionary are used as-is.
- **Level 1:** Adds standard common suffixes and prefixes (`"123"`, `"1"`, `"0"`, `"!"`, `"@"`, `"2026"`, `"2025"`).
- **Level 2:** Reverses words (`word[::-1]`) and appends extended tails/suffixes (e.g., `"12345"`, `"777"`, `"007"`, `"_!"`, `"pass"`).
- **Level 3 (Hashcat-style lite):** Structural rules including case swapping (`swapcase()`), word doubling (`adminadmin`), left/right character truncation, and cyclic shifts.
- **Level 4:** Leetspeak transformations (`1337-speak`), replacing standard letters with visually similar numbers/symbols.
- **Level 5:** Word pair combinations, joining frequent words using common separators (`""`, `"_"`, `"-"`, `"."`).

---

### Explicit Target Type (`-t`, `--type`)

By default, the tool automatically detects the target type based on the file extension (or defaults to `string` if no extension is present). 

However, if you want to override auto-detection or enforce a specific handler, you can explicitly set the type using the `-t` or `--type` flag:

```bash
python main.py 1.pdf -t string -d -s -l
```

---

## 💡 Smart Features & File Structure

### 📂 Automatic Output Generation
You don't need to manually create folders to save your results. The `output/` directory is **automatically created** upon successfully cracking the first password, storing your results safely without cluttering the project root.

### ⚡ Automatic Path Resolution (`data/` folder)
The tool is designed for maximum convenience:
* If you place your **wordlists** and **attack targets** directly inside the `data/` folder, you can reference them by name instead of typing the absolute path, the CLI will locate them automatically.

---

## Examples

Run the tool via `main.py` by passing your target and desired options:

```bash
python main.py <target> [flags]
```

> 💡 **Need all available flags?** Check the [CLI Options Reference](#cli-options-reference) below or run `python main.py --help`.

### 1. String Target (Auto-detect length)

| Command | Description |
| :--- | :--- |
| `python main.py secret -l` | Only lowercase letters (`a-z`), hybrid mode (default) |
| `python main.py secret -l -d` | Lowercase letters + digits (`0-9`) |
| `python main.py secret -l -d -s` | Lowercase letters, digits + symbols |
| `python main.py secret -l -d -s -u` | All charsets (lower, digits, symbols, upper) |
| `python main.py secret -l -m bruteforce_only` | Lowercase letters, brute-force mode |
| `python main.py secret -l -d -m dictionary_only` | Lowercase letters, digits, dictionary mode |

### 2. File Target (Path)

| Command | Description |
| :--- | :--- |
| `python main.py data/secret_zip.zip -l --min 1 --max 6` | Lowercase letters, length range 1–6 |
| `python main.py data/secret_pdf.pdf -l -w data/top_passwords.txt` | Path to password dict, hybrid mode (default) |
| `python main.py data/secret_doc.doc -w data/top_words.txt -m dictionary_only` | Path to password dict, dictionary mode |
| `python main.py data/secret_7z.7z -w data/words.txt --mangling 1` | Dictionary mode with mangling rules level 1 |

---

## Configuration & Defaults

Instead of passing multiple flags every time, you can directly edit a JSON configuration file.

The tool automatically loads its configuration by default. Here are the **default settings** used under the hood:

```json
{
  "target_type": "auto",
  "target_value": "",
  "wordlist_name": "100k_passwords.txt",
  "mode": "hybrid",
  "mangling_level": 0,
  "min_length": 1,
  "max_length": 5,
  "use_digits": false,
  "use_uppercase": false,
  "use_lowercase": false,
  "use_symbols": false
}
```

If you want to use a custom configuration file instead of the default one, specify it via `--config`:

```bash
python main.py secret.zip --config custom_config.json
```

---

## CLI Options Reference

```text
positional arguments:
  target                Target string or path to file

options:
  -h, --help            show this help message and exit
  --min MIN_LENGTH      Minimum password length
  --max MAX_LENGTH      Maximum password length
  --config CONFIG       Path to configuration file

Attack & Wordlist Settings:
  -t, --type {auto,string,zip,7z,rar,pdf,office}
                        Target type specification (default: auto-detect from extension).
  -m, --mode {hybrid,bruteforce_only,dictionary_only}
                        Attack mode
  -w, --wordlist WORDLIST_NAME
                        Wordlist filename or path.
  --mangling {1,2,3,4,5}

Charset Controls:
  -l, --lower           Enable lowercase letters (a-z)
  -nl, --no-lower       Disable lowercase letters
  -u, --upper           Enable uppercase letters (A-Z)
  -nu, --no-upper       Disable uppercase letters
  -d, --digits          Enable digits (0-9)
  -nd, --no-digits      Disable digits
  -s, --symbols         Enable symbols (punctuation)
  -ns, --no-symbols     Disable symbols
```

---

## License

Distributed under the **MIT License**. See the `LICENSE` file for more details.

---
Maintained by [MeksRa](https://github.com/MeksRa)