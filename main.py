import argparse
import multiprocessing as mp
from pathlib import Path

from rich.console import Console

from brute_force_cli.cracker import PasswordCracker

console = Console()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Professional CLI Password Cracker for archives, documents, and strings."
    )

    # Main arg, target of the attack
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Path to the target file (ZIP, 7Z, RAR, PDF, Office) or a string to test.",
    )

    # Optional flag for the target type (default = 'auto')
    parser.add_argument(
        "-t",
        "--target-type",
        default="auto",
        choices=["auto", "string", "zip", "7z", "rar", "pdf", "office"],
        help="Target type specification (default: auto-detect from extension).",
    )

    # Mode ("dictionary_only", "bruteforce_only", "hybrid")
    parser.add_argument(
        "-m",
        "--mode",
        choices=["dictionary_only", "bruteforce_only", "hybrid"],
        help="Cracking mode (overrides config.json if specified).",
    )

    # Mangling level
    parser.add_argument(
        "--mangling",
        type=int,
        choices=[0, 1, 2, 3, 4, 5],
        help="Mangling level for dictionary mutations (0-5).",
    )

    # Path to config
    parser.add_argument(
        "-c",
        "--config",
        default="config.json",
        help="Path to configuration JSON file (default: config.json).",
    )

    return parser.parse_args()


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    args = parse_arguments()
    config_path = base_dir / args.config

    try:
        # Initialize the cracker.
        cracker = PasswordCracker(config_path=config_path, base_dir=base_dir)

        # If the user provided a target using command line args,
        # override the value from the config.
        if args.target:
            cracker.target_value = args.target

        # If the target type is explicitly specified (and differs from auto), or if we want
        # to take the --target-type flag into account alongside auto-detection:
        if args.target_type != "auto":
            cracker.target_type = args.target_type
        elif args.target:
            # If the target argument was passed but the type was not specified (set to auto),
            # trigger auto-detection for the new target
            cracker.target_type = cracker._autodetect_target_type(cracker.target_value)

        # Override the mode if passed through a flag
        if args.mode:
            cracker.mode = args.mode

        # Override the mangling level if passed through a flag
        if args.mangling is not None:
            cracker.mangling_level = args.mangling

        # Run Cracker
        cracker.run()

    except Exception as e:  # noqa: BLE001
        print(f"[-] Fatal Error: {e}")


if __name__ == "__main__":
    mp.freeze_support()

    console.rule("[bold cyan]Password Cracker Utility[/]")
    console.print("[dim green]• MeksRa CLI BruteForce[/]\n")
    
    main()
