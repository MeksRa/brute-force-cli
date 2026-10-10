import io
from pathlib import Path

import msoffcrypto
import py7zr
import pypdf
import pyzipper
import rarfile

# CRITICAL: Must be at the module top level so multiprocessing worker processes inherit it on Windows
rarfile.UNRAR_TOOL = r"C:\Program Files\WinRAR\UnRAR.exe"


def verify_single_password(
    target_type: str, target_value: str, base_dir: Path, guess: str
) -> bool:
    """Verifies a single password against the specified target type."""
    if target_type == "string":
        return guess == target_value

    target_file_path: Path = base_dir / target_value

    if target_type == "zip":
        try:
            with pyzipper.AESZipFile(target_file_path) as zf:
                zf.read(zf.namelist()[0], pwd=guess.encode("utf-8"))
                return True
        except Exception:  # noqa: BLE001
            return False

    if target_type == "7z":
        try:
            with py7zr.SevenZipFile(target_file_path, mode="r", password=guess) as szf:
                return szf.testzip() is None
        except Exception:  # noqa: BLE001
            return False

    if target_type == "rar":
        try:
            with rarfile.RarFile(target_file_path) as rf:
                rf.setpassword(guess)
                info = rf.infolist()[0]
                with rf.open(info) as fp:
                    fp.read(1)
                return True
        except Exception:  # noqa: BLE001
            return False

    if target_type == "pdf":
        try:
            reader = pypdf.PdfReader(target_file_path)
            if not reader.is_encrypted:
                return True
            return bool(reader.decrypt(guess))
        except Exception:  # noqa: BLE001
            return False

    if target_type == "office":
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


def worker_batch_check(args: tuple) -> str | None:
    """Worker function for heavy multiprocessing modes operating on batches."""
    batch, target_type, target_value, base_dir = args
    if not batch:
        return None

    if target_type == "string":
        for word in batch:
            if word == target_value:
                return word
        return None

    for word in batch:
        if verify_single_password(target_type, target_value, base_dir, word):
            return word

    return None
