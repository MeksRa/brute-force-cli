import argparse
import multiprocessing as mp
import os
import subprocess
import sys
from pathlib import Path

from rich.console import Console

from brute_force_cli.cracker import PasswordCracker

console = Console()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CLI BruteForce")



    # Main arg, target of the attack
    parser.add_argument("target", type=str, help="Target string or path to file")

    # len flags
    parser.add_argument("--min", dest="min_length", type=int, default=None, help="Minimum password length")
    parser.add_argument("--max", dest="max_length", type=int, default=None, help="Maximum password length")

    parser.add_argument("--config", type=str, default="config.json", help="Path to configuration file")

    # Settings
    config_group = parser.add_argument_group("Attack & Wordlist Settings")

    # Target type
    config_group.add_argument("-t", "--type", dest="target_type", type=str, default=None, choices=["auto", "string", "zip", "7z", "rar", "pdf", "office"], help="Target type specification (default: auto-detect from extension).")

    # Mode
    config_group.add_argument("-m", "--mode", type=str, default=None, choices=["hybrid", "bruteforce_only", "dictionary_only"],help="Attack mode")

    # Wordlist
    config_group.add_argument("-w", "--wordlist", dest="wordlist_name", type=str, default=None, help="Wordlist filename or path.")

    # Mangling
    config_group.add_argument("--mangling", dest="mangling_level", type=int, default=None, choices=list(range(1, 6)),)

    # Charset controls
    charset_group = parser.add_argument_group("Charset Controls")

    # Lower
    charset_group.add_argument("-l", "--lower", dest="use_lowercase", action="store_true", default=None, help="Enable lowercase letters (a-z)")
    charset_group.add_argument("-nl", "--no-lower", dest="use_lowercase", action="store_false", help="Disable lowercase letters")

    # Upper
    charset_group.add_argument("-u", "--upper", dest="use_uppercase", action="store_true", default=None, help="Enable uppercase letters (A-Z)")
    charset_group.add_argument("-nu", "--no-upper", dest="use_uppercase", action="store_false", help="Disable uppercase letters")

    # Digits
    charset_group.add_argument("-d", "--digits", dest="use_digits", action="store_true", default=None, help="Enable digits (0-9)")
    charset_group.add_argument("-nd", "--no-digits", dest="use_digits", action="store_false", help="Disable digits")

    # Symbols
    charset_group.add_argument("-s", "--symbols", dest="use_symbols", action="store_true", default=None, help="Enable symbols (punctuation)")
    charset_group.add_argument("-ns", "--no-symbols", dest="use_symbols", action="store_false", help="Disable symbols")

    return parser.parse_args()


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    args = parse_arguments()
    config_path = base_dir / args.config

    try:
        # Initialize the cracker.
        cracker = PasswordCracker(config_path=config_path, base_dir=base_dir)

        # Apply every CLI override to the cracker *before* anything that
        # depends on the resulting state (e.g. wordlist loading depends on
        # the final mode, so `mode` must be settled first).

        # Override target if passed
        if args.target:
            cracker.target_value = args.target

        # Override mode
        if args.mode:
            cracker.mode = args.mode
            cracker.config["mode"] = args.mode

        # Override target type
        if args.target_type != "auto" and args.target_type is not None:
            cracker.target_type = args.target_type
            cracker.config["target_type"] = args.target_type
        elif args.target:
            cracker.target_type = cracker._autodetect_target_type(cracker.target_value)
            cracker.config["target_type"] = cracker.target_type

        # Override wordlist
        if args.wordlist_name:
            wordlist_arg = Path(args.wordlist_name)

            if not wordlist_arg.is_absolute() and not wordlist_arg.exists():
                cracker.wordlist_path = cracker.base_dir / "data" / args.wordlist_name
            else:
                cracker.wordlist_path = wordlist_arg

            cracker.config["wordlist_name"] = args.wordlist_name

        # Override mangling level
        if args.mangling_level is not None:
            cracker.mangling_level = args.mangling_level
            cracker.config["mangling_level"] = args.mangling_level

        # Override length parameters
        if args.min_length is not None:
            cracker.min_length = args.min_length
            cracker.config["min_length"] = args.min_length
        if args.max_length is not None:
            cracker.max_length = args.max_length
            cracker.config["max_length"] = args.max_length

        # Override charset toggles
        if args.use_lowercase is not None:
            cracker.use_lowercase = args.use_lowercase
            cracker.config["use_lowercase"] = args.use_lowercase
        if args.use_uppercase is not None:
            cracker.use_uppercase = args.use_uppercase
            cracker.config["use_uppercase"] = args.use_uppercase
        if args.use_digits is not None:
            cracker.use_digits = args.use_digits
            cracker.config["use_digits"] = args.use_digits
        if args.use_symbols is not None:
            cracker.use_symbols = args.use_symbols
            cracker.config["use_symbols"] = args.use_symbols

        # Now that target/mode/wordlist overrides are all settled, load the
        # wordlist if the *final* mode actually needs it.
        if cracker.mode in ("dictionary_only", "hybrid"):
            cracker._load_wordlist()

        try:
            # Run Cracker
            cracker.run()
        except KeyboardInterrupt:
            subprocess.run(['cls' if os.name == 'nt' else 'clear'], check=False, shell=True)
            console.print("\n[#008B8B][!] [yellow]Operation interrupted by user. Exiting...[/]")
            sys.exit(0)

    except Exception as e:  # noqa: BLE001
        console.print(f"[bold red][x] Fatal Error:[/] [red]{e}[/]")


if __name__ == "__main__":
    mp.freeze_support()

    console.rule("[bold cyan]CLI BruteForce[/]")
    
    main()
