#!/usr/bin/env bash
# ─────────────────────────────────────────────
#  Nebula CTF Toolkit — Launch Script
# ─────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$SCRIPT_DIR/python/nebula.py"
JAVA_SRC="$SCRIPT_DIR/java/Nebula.java"
JAVA_CLS="$SCRIPT_DIR/java"

case "$1" in
    java)
        echo "[*] Compiling Java engine..."
        javac -cp "$JAVA_CLS:." "$JAVA_SRC" -d "$JAVA_CLS" 2>/dev/null || {
            echo "[-] javac not found or compile error. Make sure JDK is installed."
            exit 1
        }
        echo "[+] Launching Java CLI..."
        java -cp "$JAVA_CLS" Nebula "${@:2}"
        ;;
    gui)
        echo "[*] Compiling Java engine..."
        javac -cp "$JAVA_CLS:." "$JAVA_SRC" -d "$JAVA_CLS" 2>/dev/null
        echo "[+] Launching Nebula GUI..."
        java -cp "$JAVA_CLS" Nebula --gui
        ;;
    help|--help|-h)
        echo ""
        echo "  Usage: nebula.sh [mode] [args]"
        echo ""
        echo "  Modes:"
        echo "    (no args)     Launch Python interactive shell"
        echo "    java          Launch Java CLI engine"
        echo "    gui           Launch Java Swing GUI dashboard"
        echo "    help          Show this message"
        echo ""
        ;;
    *)
        python3 "$PYTHON" "$@"
        ;;
esac
