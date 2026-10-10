import io
import logging
import os
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

# Each format's library is imported lazily, inside the function that needs
# it (see _require() below). This keeps `import brute_force_cli.verifier`
# working even if the user only installed the subset of requirements.txt
# they actually need (e.g. just pyzipper for .zip targets), and it gives a
# clear, actionable error instead of an import crash at startup.


def _require(module_name: str, package_hint: str):
    """Imports `module_name`, raising a clear error pointing at the pip
    package to install if it's missing."""
    try:
        return __import__(module_name)
    except ImportError as exc:
        raise ImportError(
            f"Missing dependency '{module_name}' (required for this target "
            f"type). Install it with: pip install {package_hint}"
        ) from exc


def _get_rarfile():
    rarfile = _require("rarfile", "rarfile")

    # CRITICAL: UNRAR_TOOL must be set before the first RarFile() call so
    # every multiprocessing worker (spawned or forked) sees it.
    #
    # Resolution order:
    #   1. BFCLI_UNRAR_TOOL env var, if the user wants to pin a specific binary.
    #   2. Whatever `unrar`/`unrar.exe` is first on PATH (covers Linux/macOS
    #      package managers and a WinRAR install that added itself to PATH).
    #   3. The common WinRAR install location, as a last-resort Windows default.
    # If none of these exist, rarfile's own default is left alone; .rar
    # targets will fail with a clear error from rarfile itself instead of
    # silently pointing at a nonexistent Windows-only path.
    candidates = (
        os.environ.get("BFCLI_UNRAR_TOOL"),
        shutil.which("unrar"),
        shutil.which("unrar.exe"),
        r"C:\Program Files\WinRAR\UnRAR.exe",
    )
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            rarfile.UNRAR_TOOL = candidate
            break

    return rarfile


def verify_single_password(
    target_type: str, target_value: str, base_dir: Path, guess: str
) -> bool:
    """Verifies a single password against the specified target type.

    Returns True on a confirmed match, False for a wrong guess *or* a
    recognized "this guess doesn't open the file" error from the
    underlying library. Unexpected errors (missing file, missing unrar
    binary, corrupt archive, programming errors) are logged once at debug
    level and also treated as "not a match" so a single bad candidate
    can't crash a long-running batch job -- but they're no longer
    invisible, which was the previous behaviour.
    """
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
        # Missing dependency is a real, actionable error -- let it propagate
        # instead of being swallowed as "wrong password".
        raise
    except Exception as exc:  # noqa: BLE001 - see docstring: intentional catch-all
        logger.debug(
            "verify_single_password: guess rejected for target_type=%s (%s)",
            target_type,
            exc,
        )
        return False

    return False


def worker_batch_check(args: tuple) -> tuple[int, str | None]:
    """Worker function for heavy multiprocessing modes operating on batches.

    Returns (batch_size, match_or_None). Returning the batch's own size
    alongside the result lets callers using imap_unordered report accurate
    attempt counts, since unordered completion means a caller can't
    otherwise line up "how many guesses were in *this* batch" with the
    result that just came back.
    """
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
