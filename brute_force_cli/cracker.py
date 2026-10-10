import itertools
import json
import multiprocessing as mp
import string
import time
from pathlib import Path

from brute_force_cli.mangling import generate_mutations
from brute_force_cli.verifier import verify_single_password, worker_batch_check


class PasswordCracker:
    def __init__(self, config_path: Path, base_dir: Path) -> None:
        self.base_dir = base_dir
        self.config = self._load_config(config_path)

        self.target_value: str = str(self.config.get("target_value", "")).strip()
        self.mode = str(self.config.get("mode", "hybrid")).lower()
        self.mangling_level = int(self.config.get("mangling_level", 0))

        raw_target_type = str(self.config.get("target_type", "")).strip().lower()
        if not raw_target_type or raw_target_type == "auto":
            self.target_type = self._autodetect_target_type(self.target_value)
        else:
            self.target_type = raw_target_type

        wordlist_name = str(self.config.get("wordlist_name", "100k_passwords.txt"))
        self.wordlist_path = self.base_dir / "data" / wordlist_name
        self._common_words: list[str] = []

        if self.mode in ("dictionary_only", "hybrid"):
            self._load_wordlist()

    def _autodetect_target_type(self, target_value: str) -> str:
        """Automatically determines the target type based on the file extension."""
        if not target_value:
            return "string"

        path = Path(target_value)
        ext = path.suffix.lower()

        extension_map = {
            ".zip": "zip",
            ".7z": "7z",
            ".rar": "rar",
            ".pdf": "pdf",
            ".docx": "office",
            ".doc": "office",
            ".xlsx": "office",
            ".xls": "office",
            ".pptx": "office",
            ".ppt": "office",
        }

        if ext in extension_map:
            return extension_map[ext]

        if not (self.base_dir / target_value).exists():
            return "string"

        return "string"

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
            with self.wordlist_path.open(
                "r", encoding="utf-8", errors="ignore"
            ) as file:
                self._common_words = [line.strip() for line in file if line.strip()]
            elapsed = time.perf_counter() - start
            print(f"[+] Loaded {len(self._common_words):,} words ({elapsed:.3f}s).")
        except Exception as e:  # noqa: BLE001
            print(f"[-] Failed to load dictionary: {e}")

    def check_dictionary(self) -> str | None:
        if not self._common_words:
            print("[-] Dictionary is empty or missing.")
            return None

        start_time = time.perf_counter()

        if self.mangling_level <= 0:
            print("[*] Level 0: Running high-speed direct dictionary check...")
            for word in self._common_words:
                if verify_single_password(
                    self.target_type, self.target_value, self.base_dir, word
                ):
                    elapsed = time.perf_counter() - start_time
                    return (
                        f"\n[!] MATCH FOUND IN DICTIONARY!\n"
                        f"    Target: '{self.target_value}' ({self.target_type})\n"
                        f"    Password: '{word}'\n"
                        f"    Time elapsed: {elapsed:.6f}s"
                    )
            print("[-] Target password not found in dictionary search.")
            return None

        cpu_count = mp.cpu_count()
        print(
            f"[*] Level {self.mangling_level}: Starting parallel mangled dictionary search across {cpu_count} CPU cores..."
        )

        unique_candidates = generate_mutations(self._common_words, self.mangling_level)
        print(
            f"[+] Generated {len(unique_candidates):,} total candidates after mangling."
        )

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
            for result in pool.imap_unordered(worker_batch_check, batches):
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

        # autocorrection if len word(target value) > max_len
        if self.target_type == "string" and len(self.target_value) > max_len:
            print(
                f"[*] Note: Target string length ({len(self.target_value)}) exceeds config max_length ({max_len}). Adjusting limit."
            )
            max_len = len(self.target_value)

        cpu_count = mp.cpu_count()
        attempts = 0
        start_time = time.perf_counter()

        print(
            f"[*] Starting parallel brute-force (length: {min_len}-{max_len}) across {cpu_count} CPU cores..."
        )
        batch_size = 5000

        with mp.Pool(processes=cpu_count) as pool:
            for length in range(min_len, max_len + 1):
                print(f"[DEBUG] Preparing batches for length {length}...")

                def batch_generator(current_len=length):
                    current_batch = []
                    for tuple_guess in itertools.product(charset, repeat=current_len):
                        current_batch.append("".join(tuple_guess))
                        if len(current_batch) >= batch_size:
                            yield current_batch
                            current_batch = []
                    if current_batch:
                        yield current_batch

                tasks = [
                    (batch, self.target_type, self.target_value, self.base_dir)
                    for batch in batch_generator()
                ]

                print(
                    f"[DEBUG] Length {length}: Generated {len(tasks)} batches. Sending to pool via imap_unordered..."
                )

                for result in pool.imap_unordered(worker_batch_check, tasks):
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
            print(
                f"[-] Unsupported target_type '{self.target_type}'. Use: {valid_targets}"
            )
            return

        if self.target_type != "string":
            target_path = Path(self.target_value)

            if not target_path.exists():
                fallback_path = self.base_dir / "data" / self.target_value
                if fallback_path.exists():
                    target_path = fallback_path

            if not target_path.exists():
                print(f"[-] Target file not found: {self.target_value}")
                return

            self.target_value = str(target_path.resolve())

        valid_modes = ("dictionary_only", "bruteforce_only", "hybrid")
        if self.mode not in valid_modes:
            print(f"[-] Invalid mode '{self.mode}'. Supported modes: {valid_modes}")
            return

        print(
            f"=== Password Cracker Started (Target: {self.target_type} | Mode: {self.mode}) ==="
        )
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
