import argparse
import logging
import re
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)

# These patterns check for different types of secrets
patterns = {
    "AWS Key": r"\bAKIA[0-9A-Z]{16}\b",
    "GitHub Token": r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b",
    "Google API Key": r"\bAIza[0-9A-Za-z_-]{35}\b",
    "Slack Token": r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
    "Private Key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "Password": r"""(?i)\bpassword\s*[:=]\s*["'][^"']{4,}["']""",
    "API Key": r"""(?i)\bapi[_-]?key\s*[:=]\s*["'][^"']{8,}["']""",
    "Access Token": (
        r"""(?i)\b(?:access[_-]?token|auth[_-]?token)\s*"""
        r"""[:=]\s*["'][^"']{8,}["']"""
    )
}


def scan_file(file_path):
    # Check one file for possible secrets
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            for line_number, line in enumerate(file, start=1):

                for secret_type, pattern in patterns.items():
                    matches = re.finditer(pattern, line)

                    for match in matches:
                        findings.append({
                            "file": str(file_path),
                            "line": line_number,
                            "type": secret_type,
                            "match": match.group()
                        })

    except OSError as error:
        logging.warning("Could not read %s: %s", file_path, error)

    return findings


def scan_path(path):
    # Check if the path is a file or folder
    if path.is_file():
        return scan_file(path)

    elif path.is_dir():
        findings = []

        for file_path in path.rglob("*"):
            if file_path.is_file():
                findings.extend(scan_file(file_path))

        return findings

    else:
        logging.error("File or folder does not exist: %s", path)
        return None


def main():
    # Let the user enter a file or folder through the command line
    parser = argparse.ArgumentParser(
        description="Scan files for possible hardcoded secrets."
    )

    parser.add_argument(
        "path",
        help="The file or folder you want to scan"
    )

    args = parser.parse_args()
    path = Path(args.path)

    logging.info("Starting scan...")

    findings = scan_path(path)

    if findings is None:
        raise SystemExit(1)

    # Show the results
    if findings:
        print("\nPossible secrets found:\n")

        for finding in findings:
            print("File:", finding["file"])
            print("Line:", finding["line"])
            print("Type:", finding["type"])
            print("Match:", finding["match"])
            print("-" * 30)

        print("Total findings:", len(findings))

    else:
        print("\nNo matching patterns found.")

    logging.info("Scan finished.")


if __name__ == "__main__":
    main()
