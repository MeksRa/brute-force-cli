import io
import itertools
import json
import multiprocessing as mp
import string
import time
from pathlib import Path

import msoffcrypto
import py7zr
import pypdf
import pyzipper
import rarfile

# CRITICAL: Must be at the module top level so multiprocessing worker processes inherit it on Windows
rarfile.UNRAR_TOOL = r"C:\Program Files\WinRAR\UnRAR.exe"


def _generate_mutations(word: str, level: int) -> set[str]:
    """Generates password mutations dynamically based on the configured mangling level."""
    mutations = {word, word.lower(), word.capitalize()}
    if level >= 1:
        mutations.update({word.upper(), word.title()})

    if level == 1:
        return mutations

    suffixes_l2 = ("", "1", "123", "!")
    extended = set()
    for m in mutations:
        for s in suffixes_l2:
            extended.add(m + s)

    if level >= 3:
        suffixes_l3 = ("2026", "123456", "#", "@", "12345")
        for m in mutations:
            for s in suffixes_l3:
                extended.add(m + s)
        return extended

    return extended


def _worker_batch_check(args: tuple) -> str | None:
    """Worker function for heavy multiprocessing modes."""
    batch, target_type, target_value, base_dir = args
    if not batch:
        return None

    # 1) String (doesn't use file path)
    if target_type == "string":
        for word in batch:
            if word == target_value:
                return word
        return None

    # Guaranteed Path for all file-based targets (removes type checker warnings)
    target_file_path: Path = base_dir / target_value

    if target_type == "zip":
        for word in batch:
            try:
                with pyzipper.AESZipFile(target_file_path) as zf:
                    first_file = zf.namelist()[0]
                    zf.read(first_file, pwd=word.encode("utf-8"))
                    return word
            except Exception:  # noqa: BLE001, S110
                pass
        return None

    if target_type == "7z":
        for word in batch:
            try:
                with py7zr.SevenZipFile(target_file_path, mode="r", password=word) as szf:
                    if szf.testzip() is None:
                        return word
            except Exception:  # noqa: BLE001, S110
                pass
        return None

    if target_type == "rar":
        for word in batch:
            try:
                with rarfile.RarFile(target_file_path) as rf:
                    rf.setpassword(word)
                    info = rf.infolist()[0]
                    with rf.open(info) as fp:
                        fp.read(1)
                    return word
            except Exception:  # noqa: BLE001, S110
                pass
        return None

    if target_type == "pdf":
        for word in batch:
            try:
                reader = pypdf.PdfReader(target_file_path)
                if not reader.is_encrypted or reader.decrypt(word):
                    return word
            except Exception:  # noqa: BLE001, S110
                pass
        return None

    if target_type == "office":
        for word in batch:
            try:
                with open(target_file_path, "rb") as f:
                    office_file = msoffcrypto.OfficeFile(f)
                    office_file.load_key(password=word)
                    dummy = io.BytesIO()
                    office_file.decrypt(dummy)
                    return word
            except Exception:  # noqa: BLE001, S110
                pass
        return None

    return None


class PasswordCracker:
    def __init__(self, config_path: Path, base_dir: Path) -> None:
        self.base_dir = base_dir
        self.config = self._load_config(config_path)

        self.target_type: str = str(self.config.get("target_type", "string")).lower()
        self.target_value: str = str(self.config.get("target_value", "")).strip()
        self.mode = str(self.config.get("mode", "hybrid")).lower()
        self.mangling_level = int(self.config.get("mangling_level", 0))

        wordlist_name = str(self.config.get("wordlist_name", "100k_passwords.txt"))
        self.wordlist_path = self.base_dir / "data" / wordlist_name
        self._common_words: list[str] = []

        if self.mode in ("dictionary_only", "hybrid"):
            self._load_wordlist()

    def _load_config(self, path: Path) -> dict:
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        try:
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format in {path.name}: {e}") from e

    def _load_wordlist(self) -> None:
        if not self.wordlist_path.exists():
            print(f"[-] Wordlist file not found: {self.wordlist_path}")
            return

        try:
            start = time.perf_counter()
            with self.wordlist_path.open("r", encoding="utf-8", errors="ignore") as file:
                self._common_words = [line.strip() for line in file if line.strip()]
            elapsed = time.perf_counter() - start
            print(f"[+] Loaded {len(self._common_words):,} words ({elapsed:.3f}s).")
        except Exception as e:  # noqa: BLE001
            print(f"[-] Failed to load dictionary: {e}")

    def verify_password(self, guess: str) -> bool:
        """Lightning-fast single verification for Level 0 (zero overhead)."""
        if self.target_type == "string":
            return guess == self.target_value

        target_file_path: Path = self.base_dir / self.target_value

        if self.target_type == "zip":
            try:
                with pyzipper.AESZipFile(target_file_path) as zf:
                    zf.read(zf.namelist()[0], pwd=guess.encode("utf-8"))
                    return True
            except Exception:  # noqa: BLE001
                return False

        if self.target_type == "7z":
            try:
                with py7zr.SevenZipFile(target_file_path, mode="r", password=guess) as szf:
                    return szf.testzip() is None
            except Exception:  # noqa: BLE001
                return False

        if self.target_type == "rar":
            try:
                with rarfile.RarFile(target_file_path) as rf:
                    rf.setpassword(guess)
                    info = rf.infolist()[0]
                    with rf.open(info) as fp:
                        fp.read(1)
                    return True
            except Exception:  # noqa: BLE001
                return False

        if self.target_type == "pdf":
            try:
                reader = pypdf.PdfReader(target_file_path)
                if not reader.is_encrypted:
                    return True
                return bool(reader.decrypt(guess))
            except Exception:  # noqa: BLE001
                return False

        if self.target_type == "office":
            try:
                with open(target_file_path, "rb") as f:
                    office_file = msoffcrypto.OfficeFile(f)
                    office_file.load_key(password=guess)
                    dummy = io.BytesIO()
                    office_file.decrypt(dummy)
                    return True
            except Exception:  # noqa: BLE001
                return False

        return False

    def check_dictionary(self) -> str | None:
        """Smart router: Level 0 runs instantly with zero overhead; Level 1+ uses multiprocessing."""
        if not self._common_words:
            print("[-] Dictionary is empty or missing.")
            return None

        start_time = time.perf_counter()

        # ==========================================
        # LEVEL 0: ZERO OVERHEAD (Pure lightning speed)
        # ==========================================
        if self.mangling_level <= 0:
            print("[*] Level 0: Running high-speed direct dictionary check...")
            for word in self._common_words:
                if self.verify_password(word):
                    elapsed = time.perf_counter() - start_time
                    return (
                        f"\n[!] MATCH FOUND IN DICTIONARY!\n"
                        f"    Target: '{self.target_value}' ({self.target_type})\n"
                        f"    Password: '{word}'\n"
                        f"    Time elapsed: {elapsed:.6f}s"
                    )
            print("[-] Target password not found in dictionary search.")
            return None

        # ==========================================
        # LEVEL 1+: MULTIPROCESSING WITH MANGLING
        # ==========================================
        cpu_count = mp.cpu_count()
        print(f"[*] Level {self.mangling_level}: Starting parallel mangled dictionary search across {cpu_count} CPU cores...")

        mangled_candidates = []
        for word in self._common_words:
            mangled_candidates.extend(_generate_mutations(word, self.mangling_level))
        unique_candidates = list(dict.fromkeys(mangled_candidates))
        print(f"[+] Generated {len(unique_candidates):,} total candidates after mangling.")

        batch_size = 1000
        batches = [
            (
                unique_candidates[i : i + batch_size],
                self.target_type,
                self.target_value,
                self.base_dir,
            )
            for i in range(0, len(unique_candidates), batch_size)
        ]

        with mp.Pool(processes=cpu_count) as pool:
            for result in pool.imap_unordered(_worker_batch_check, batches):
                if result:
                    pool.terminate()
                    elapsed = time.perf_counter() - start_time
                    return (
                        f"\n[!] MATCH FOUND VIA MANGLED DICTIONARY!\n"
                        f"    Target: '{self.target_value}' ({self.target_type})\n"
                        f"    Password: '{result}'\n"
                        f"    Time elapsed: {elapsed:.2f}s"
                    )

        print("[-] Target password not found in dictionary search.")
        return None

    def brute_force(self) -> str | None:
        """Parallel batched brute-force across multiple CPU cores."""
        charset = string.ascii_lowercase
        if self.config.get("use_uppercase"):
            charset += string.ascii_uppercase
        if self.config.get("use_digits"):
            charset += string.digits
        if self.config.get("use_symbols"):
            charset += string.punctuation

        try:
            min_len = int(self.config.get("min_length", 1))
            max_len = int(self.config.get("max_length", 5))
        except ValueError:
            print("[-] Invalid length settings in config.json. Must be integers.")
            return None

        if min_len < 1 or max_len < min_len:
            print("[-] Invalid length bounds (min_length > max_length or < 1).")
            return None

        cpu_count = mp.cpu_count()
        attempts = 0
        start_time = time.perf_counter()

        print(f"[*] Starting parallel brute-force (length: {min_len}-{max_len}) across {cpu_count} CPU cores...")
        batch_size = 5000

        for length in range(min_len, max_len + 1):
            def batch_generator():
                current_batch = []
                for tuple_guess in itertools.product(charset, repeat=length):
                    current_batch.append("".join(tuple_guess))
                    if len(current_batch) >= batch_size:
                        yield current_batch
                        current_batch = []
                if current_batch:
                    yield current_batch

            with mp.Pool(processes=cpu_count) as pool:
                tasks = (
                    (batch, self.target_type, self.target_value, self.base_dir)
                    for batch in batch_generator()
                )

                for result in pool.imap_unordered(_worker_batch_check, tasks):
                    attempts += batch_size
                    if result:
                        pool.terminate()
                        elapsed = time.perf_counter() - start_time
                        speed = attempts / elapsed if elapsed > 0 else 0
                        return (
                            f"\n[+] SUCCESS! Password cracked!\n"
                            f"    Target: '{self.target_value}' ({self.target_type})\n"
                            f"    Password: '{result}'\n"
                            f"    Attempts evaluated: ~{attempts:,}\n"
                            f"    Time elapsed: {elapsed:.2f}s\n"
                            f"    Speed: {speed:,.0f} attempts/sec"
                        )

        elapsed = time.perf_counter() - start_time
        print(f"[-] Password not found after search ({elapsed:.2f}s).")
        return None

    def run(self) -> None:
        if not self.target_value:
            print("[-] Error: 'target_value' in config.json is empty.")
            return

        valid_targets = ("string", "zip", "7z", "rar", "pdf", "office")
        if self.target_type not in valid_targets:
            print(f"[-] Unsupported target_type '{self.target_type}'. Use: {valid_targets}")
            return

        if self.target_type != "string":
            target_file_path = self.base_dir / self.target_value
            if not target_file_path.exists():
                print(f"[-] Target file not found: {target_file_path}")
                return

        valid_modes = ("dictionary_only", "bruteforce_only", "hybrid")
        if self.mode not in valid_modes:
            print(f"[-] Invalid mode '{self.mode}'. Supported modes: {valid_modes}")
            return

        print(f"=== Password Cracker Started (Target: {self.target_type} | Mode: {self.mode}) ===")
        start_total = time.perf_counter()

        if self.mode == "dictionary_only":
            if result := self.check_dictionary():
                print(result)
        elif self.mode == "bruteforce_only":
            if result := self.brute_force():
                print(result)
        elif self.mode == "hybrid":
            result = self.check_dictionary()
            if result:
                print(result)
            else:
                if result_bf := self.brute_force():
                    print(result_bf)

        total_elapsed = time.perf_counter() - start_total
        print(f"\n[=] Total execution time: {total_elapsed:.4f}s")


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    config_path = base_dir / "config.json"

    try:
        cracker = PasswordCracker(config_path=config_path, base_dir=base_dir)
        cracker.run()
    except Exception as e:  # noqa: BLE001
        print(f"[-] Fatal Error: {e}")


if __name__ == "__main__":
    mp.freeze_support()
    main()