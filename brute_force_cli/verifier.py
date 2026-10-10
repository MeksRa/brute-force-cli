import io
import logging
import os
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

_cached_rarfile = None


def _require(module_name: str, package_hint: str):
    try:
        return __import__(module_name)
    except ImportError as exc:
        raise ImportError(
            f"Missing dependency '{module_name}' (required for this target "
            f"type). Install it with: pip install {package_hint}"
        ) from exc


def _get_rarfile():
    global _cached_rarfile
    if _cached_rarfile is not None:
        return _cached_rarfile

    rarfile = _require("rarfile", "rarfile")
    candidates = (
        os.environ.get("BFCLI_UNRAR_TOOL"),
        shutil.which("unrar"),
        shutil.which("unrar.exe"),
        r"C:\Program Files\WinRAR\UnRAR.exe",
        r"C:\Program Files (x86)\WinRAR\UnRAR.exe",
        "/usr/bin/unrar",
        "/usr/local/bin/unrar",
        "/opt/homebrew/bin/unrar",
    )
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            rarfile.UNRAR_TOOL = candidate
            break

    _cached_rarfile = rarfile
    return rarfile


def verify_single_password(
    target_type: str, target_value: str, base_dir: Path, guess: str
) -> bool:
    if target_type == "string":
        return guess == target_value

    target_file_path: Path = base_dir / target_value

    try:
        if target_type == "zip":
            pyzipper = _require("pyzipper", "pyzipper")
            with pyzipper.AESZipFile(target_file_path) as zf:
                zf.read(zf.namelist()[0], pwd=guess.encode("utf-8"))
                return True

        if target_type == "7z":
            py7zr = _require("py7zr", "py7zr")
            with py7zr.SevenZipFile(target_file_path, mode="r", password=guess) as szf:
                return szf.testzip() is None

        if target_type == "rar":
            rarfile = _get_rarfile()
            with rarfile.RarFile(target_file_path) as rf:
                rf.setpassword(guess)
                info = rf.infolist()[0]
                with rf.open(info) as fp:
                    fp.read(1)
                return True

        if target_type == "pdf":
            pypdf = _require("pypdf", "pypdf")
            reader = pypdf.PdfReader(target_file_path)
            if not reader.is_encrypted:
                return True
            return bool(reader.decrypt(guess))

        if target_type == "office":
            msoffcrypto = _require("msoffcrypto", "msoffcrypto-tool")
            with open(target_file_path, "rb") as f:
                office_file = msoffcrypto.OfficeFile(f)
                office_file.load_key(password=guess)
                dummy = io.BytesIO()
                office_file.decrypt(dummy)
                return True

    except ImportError:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.debug(
            "verify_single_password: guess rejected for target_type=%s (%s)",
            target_type,
            exc,
        )
        return False

    return False


def worker_batch_check(args: tuple) -> tuple[int, str | None]:
    batch, target_type, target_value, base_dir = args
    if not batch:
        return 0, None

    if target_type == "string":
        for word in batch:
            if word == target_value:
                return len(batch), word
        return len(batch), None

    for word in batch:
        if verify_single_password(target_type, target_value, base_dir, word):
            return len(batch), word

    return len(batch), None