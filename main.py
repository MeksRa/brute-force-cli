import multiprocessing as mp
from pathlib import Path

from brute_force_cli.cracker import PasswordCracker


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    config_path = base_dir / "config.json"

    try:
        cracker = PasswordCracker(config_path=config_path, base_dir=base_dir)
        cracker.run()
    except Exception as e:
        print(f"[-] Fatal Error: {e}")


if __name__ == "__main__":
    mp.freeze_support()
    main()