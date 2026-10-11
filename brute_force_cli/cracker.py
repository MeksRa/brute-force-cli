import itertools
import json
import multiprocessing as mp
import os
import stat
import string
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from brute_force_cli.mangling import generate_mutations
from brute_force_cli.verifier import worker_batch_check

console = Console()


class PasswordCracker:
    def __init__(self, config_path: Path, base_dir: Path) -> None:
        self.base_dir = base_dir
        self.config = self._load_config(config_path)

        self.target_value: str = str(self.config.get("target_value", "")).strip()
        self.mode = str(self.config.get("mode", "hybrid")).lower()
        self.mangling_level = int(self.config.get("mangling_level", 0))

        self.min_length = int(self.config.get("min_length", 1))
        self.max_length = int(self.config.get("max_length", 5))

        self.use_lowercase = bool(self.config.get("use_lowercase", True))
        self.use_uppercase = bool(self.config.get("use_uppercase", False))
        self.use_digits = bool(self.config.get("use_digits", True))
        self.use_symbols = bool(self.config.get("use_symbols", False))

        raw_target_type = str(self.config.get("target_type", "")).strip().lower()
        if not raw_target_type or raw_target_type == "auto":
            self.target_type = self._autodetect_target_type(self.target_value)
        else:
            self.target_type = raw_target_type

        wordlist_name = str(self.config.get("wordlist_name", "100k_passwords.txt"))
        self.wordlist_path = self.base_dir / "data" / wordlist_name
        self._common_words: list[str] = []

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

        # No recognized extension: treat it as a literal target string.
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
            console.print(f"[bold red][x] Error:[/] [red]Wordlist file not found: {self.wordlist_path}[/]")
            return

        try:
            start = time.perf_counter()
            with self.wordlist_path.open(
                "r", encoding="utf-8", errors="ignore"
            ) as file:
                self._common_words = [line.strip() for line in file if line.strip()]
            elapsed = time.perf_counter() - start
            console.print(f"[#20B2AA][✓] [green]Loaded {len(self._common_words):,} words ({elapsed:.3f}s).[/]")
            console.print(f"[#008B8B][i] [green]Wordlist:[/] [dim cyan]{self.wordlist_path}[/]")
        except Exception as e:  # noqa: BLE001
            console.print(f"[bold red][x] Error:[/] [red]Failed to load dictionary: {e}[/]")

    def _build_charset(self) -> str:
        """Builds the active charset from the (CLI-overridable) instance flags.

        These attributes, not self.config, are the single source of truth:
        main.py updates both when a CLI flag is passed, but only the
        attributes are guaranteed to reflect the final, merged state.
        """
        charset = ""
        if self.use_lowercase:
            charset += string.ascii_lowercase
        if self.use_uppercase:
            charset += string.ascii_uppercase
        if self.use_digits:
            charset += string.digits
        if self.use_symbols:
            charset += string.punctuation
        return charset

    def check_dictionary(self) -> str | None:
        if not self._common_words:
            console.print("[bold red][x] Error:[/] [red]Dictionary is empty or missing.[/]")
            return None

        start_time = time.perf_counter()

        if self.mangling_level <= 0:
            candidates = self._common_words
            console.print(f"[#20B2AA][>] [cyan]Level 0: Running parallel direct dictionary check across {mp.cpu_count()} CPU cores...[/]")
        else:
            cpu_count = mp.cpu_count()
            console.print(f"[#20B2AA][>] [cyan]Level {self.mangling_level}: Starting parallel mangled dictionary search across {cpu_count} CPU cores...[/]")
            candidates = generate_mutations(self._common_words, self.mangling_level)
            console.print(f"[#20B2AA][i] [green]Generated {len(candidates):,} total candidates after mangling.[/]")
        cpu_count = mp.cpu_count()
        batch_size = 1000
        batches = [
            (
                candidates[i : i + batch_size],
                self.target_type,
                self.target_value,
                self.base_dir,
            )
            for i in range(0, len(candidates), batch_size)
        ]

        with mp.Pool(processes=cpu_count) as pool:
            for _batch_size, result in pool.imap_unordered(worker_batch_check, batches):
                if result:
                    pool.terminate()
                    elapsed = time.perf_counter() - start_time
                    console.print(
                        f"\n[bold #20B2AA][✓] [bold green]MATCH FOUND IN DICTIONARY![/]\n"
                        f"    [gray]Target:[/] '{self.target_value}' ({self.target_type})\n"
                        f"    [bold green]Password:[/] '{result}'\n"
                        f"    [gray]Time elapsed:[/] {elapsed:.4f}s"
                    )
                    return result

        console.print("[#008B8B][i] [yellow]Target password not found in dictionary search.[/]")
        return None

    def brute_force(self) -> str | None:
        charset = self._build_charset()

        if not charset:
            console.print(
                "[bold red][x] Error:[/] [red]Charset is empty! Enable at least one character set in config.json.[/]"
            )
            return None

        min_len = self.min_length
        max_len = self.max_length

        if min_len < 1 or max_len < min_len:
            console.print(
                "[bold red][x] Error:[/] [red]Invalid length bounds (min_length > max_length or < 1).[/]"
            )
            return None

        # Autocorrect if length of target value exceeds max_len
        if self.target_type == "string" and len(self.target_value) > max_len:
            console.print(
                f"[#008B8B][i] [yellow]Note: Target string length ({len(self.target_value)}) exceeds config max_length ({max_len}). Adjusting limit.[/]"
            )
            max_len = len(self.target_value)

        # Autocorrect min_len for string target
        if self.target_type == "string":
            min_len = max_len = len(self.target_value)

        cpu_count = mp.cpu_count()
        attempts = 0
        start_time = time.perf_counter()

        # Display current configuration summary for transparency
        console.print(
            f"[#008B8B][i] [cyan]Configuration summary:[/]\n"
            f"    [gray]• Lowercase letters (use_lowercase):[/] {self._format_bool(self.use_lowercase)}\n"
            f"    [gray]• Uppercase letters (use_uppercase):[/] {self._format_bool(self.use_uppercase)}\n"
            f"    [gray]• Digits (use_digits):[/] {self._format_bool(self.use_digits)}\n"
            f"    [gray]• Symbols (use_symbols):[/] {self._format_bool(self.use_symbols)}\n"
            f"    [gray]• Mangling level (mangling_level):[/] [#FFB86C]{self.mangling_level}[/]\n"
            f"    [gray]• Length range:[/] [#FFB86C]{min_len} - {max_len}[/]\n"
            f"    [gray]• Total charset size:[/] [#FFB86C]{len(charset)}[/]"
        )
        console.print(
            f"[#20B2AA][>] [cyan]Starting parallel brute-force (length: {min_len}-{max_len}) across {cpu_count} CPU cores...[/]"
        )

        # Adaptive batch size: smaller for heavy files to keep UI responsive, larger for strings to maximize throughput
        batch_size = 100 if self.target_type != "string" else 10000

        with (
            mp.Pool(processes=cpu_count) as pool,
            Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                "[progress.percentage]{task.percentage:>3.1f}%",
                TimeElapsedColumn(),
                "•",
                TimeRemainingColumn(),
                console=console,
            ) as progress,
        ):
            # Create a single task once before the loop to prevent stacking bars
            task_id = progress.add_task("[cyan]Preparing...", total=100)

            for length in range(min_len, max_len + 1):
                total_combinations = len(charset) ** length

                # Update task description, total combinations, and reset progress for the new length
                progress.update(
                    task_id,
                    description=f"[cyan]Length {length}[/]",
                    total=total_combinations,
                    completed=0,
                )

                def batch_generator(current_len=length):
                    current_batch = []
                    join = "".join
                    for tuple_guess in itertools.product(charset, repeat=current_len):
                        current_batch.append(join(tuple_guess))
                        if len(current_batch) >= batch_size:
                            yield (
                                current_batch,
                                self.target_type,
                                self.target_value,
                                self.base_dir,
                            )
                            current_batch = []
                    if current_batch:
                        yield (
                            current_batch,
                            self.target_type,
                            self.target_value,
                            self.base_dir,
                        )

                for batch_len, result in pool.imap_unordered(
                    worker_batch_check, batch_generator(), chunksize=4
                ):
                    attempts += batch_len
                    progress.update(task_id, advance=batch_len)
                    if result:
                        progress.update(task_id, completed=total_combinations)
                        pool.terminate()
                        elapsed = time.perf_counter() - start_time
                        speed = attempts / elapsed if elapsed > 0 else 0
                        self.save_successful_result(self.target_value, result)
                        console.print(
                            f"\n[bold #20B2AA][✓] [bold green]SUCCESS! Password cracked![/]\n"
                            f"    [gray]Target:[/] '{self.target_value}' ({self.target_type})\n"
                            f"    [bold green]Password:[/] '{result}'\n"
                            f"    [gray]Attempts evaluated:[/] ~{attempts:,}\n"
                            f"    [gray]Time elapsed:[/] {elapsed:.2f}s\n"
                            f"    [gray]Speed:[/] {speed:,.0f} attempts/sec"
                        )
                        return result

        elapsed = time.perf_counter() - start_time
        console.print(f"[#008B8B][i] [yellow]Password not found after search ({elapsed:.2f}s).[/]")
        return None

    def run(self) -> None:
        if not self.target_value:
            console.print("[bold red][x] Error:[/] [red]'target_value' in config.json is empty.[/]")
            return

        valid_targets = ("string", "zip", "7z", "rar", "pdf", "office")
        if self.target_type not in valid_targets:
            console.print(f"[bold red][x] Error:[/] [red]Unsupported target_type '{self.target_type}'. Use: {valid_targets}[/]")
            return

        if self.target_type != "string":
            target_path = Path(self.target_value)

            if not target_path.exists():
                fallback_path = self.base_dir / "data" / self.target_value
                if fallback_path.exists():
                    target_path = fallback_path

            if not target_path.exists():
                console.print(f"[bold red][x] Error:[/] [red]Target file not found: {self.target_value}[/]")
                return

            self.target_value = str(target_path.resolve())

        valid_modes = ("dictionary_only", "bruteforce_only", "hybrid")
        if self.mode not in valid_modes:
            console.print(f"[bold red][x] Error:[/] [red]Invalid mode '{self.mode}'. Supported modes: {valid_modes}[/]")
            return


        console.print(f"[#008B8B]===[/] [bold #20B2AA]Password Cracker Started[/] [#008B8B](Target: {self.target_type} | Mode: {self.mode}) ===[/]")
        start_total = time.perf_counter()

        result = None
        if self.mode == "dictionary_only":
            result = self.check_dictionary()
        elif self.mode == "bruteforce_only":
            result = self.brute_force()
        elif self.mode == "hybrid":
            result = self.check_dictionary()
            if not result:
                result = self.brute_force()

        total_elapsed = time.perf_counter() - start_total
        console.print(f"\n[#20B2AA][i] [cyan]Total execution time: {total_elapsed:.4f}s[/]")
        console.rule()

    def save_successful_result(self, target_name, password):
        """Appends a found password to base_dir/output/passwords.txt.

        Uses base_dir (not the process CWD) so the output location doesn't
        depend on where the CLI happens to be invoked from, and restricts
        the file to owner-only read/write since it stores recovered
        secrets in plaintext.
        """
        output_dir = self.base_dir / "output"
        output_dir.mkdir(parents=True, exist_ok=True)

        file_path = output_dir / "passwords.txt"
        timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")

        with open(file_path, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] Target: {target_name} | Password: {password}\n")

        try:
            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            # Best-effort on platforms/filesystems that don't support chmod
            # (e.g. some Windows/FAT setups); not worth failing the run over.
            pass

    def _format_bool(self, val):
        return "[bold green]True[/]" if val else "[dim red]False[/]"
