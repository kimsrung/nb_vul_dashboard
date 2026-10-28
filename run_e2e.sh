#!/usr/bin/env bash
# ==============================================================================
# Automated Browser Integration Test Runner (Playwright E2E)
# Usage:
#   ./run_e2e.sh                 # Runs all suites with visible desktop browser (1000ms slowmo)
#   ./run_e2e.sh --slowmo 1500   # Custom slowdown pace (e.g. 1500ms)
#   ./run_e2e.sh --headless      # Runs all suites headless in background (CI/CD)
#   ./run_e2e.sh --fast          # Runs visible browser at full speed
#   ./run_e2e.sh test_01         # Runs only test_01_auth_and_rbac.py
#   ./run_e2e.sh test_02         # Runs only test_02_assets_and_remediation.py
#   ./run_e2e.sh test_03         # Runs only test_03_alerts_lifecycle.py
#   ./run_e2e.sh test_04         # Runs only test_04_misp_threat_intel.py
#   ./run_e2e.sh test_05         # Runs only test_05_admin_governance.py
# ==============================================================================

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_URL="${E2E_BASE_URL:-http://localhost:3000}"

PYTEST_CMD=()

# 1. Check local backend venv (Linux/macOS bin/ or Windows Scripts/)
if [ -f "${DIR}/backend/venv/bin/pytest" ]; then
    PYTEST_CMD=("${DIR}/backend/venv/bin/pytest")
elif [ -f "${DIR}/backend/venv/Scripts/pytest.exe" ]; then
    PYTEST_CMD=("${DIR}/backend/venv/Scripts/pytest.exe")
elif [ -f "${DIR}/backend/venv/Scripts/pytest" ]; then
    PYTEST_CMD=("${DIR}/backend/venv/Scripts/pytest")
# 2. Check root-level venv (if created at project root)
elif [ -f "${DIR}/venv/bin/pytest" ]; then
    PYTEST_CMD=("${DIR}/venv/bin/pytest")
elif [ -f "${DIR}/venv/Scripts/pytest.exe" ]; then
    PYTEST_CMD=("${DIR}/venv/Scripts/pytest.exe")
elif [ -f "${DIR}/venv/Scripts/pytest" ]; then
    PYTEST_CMD=("${DIR}/venv/Scripts/pytest")
# 3. Check active virtualenv from environment ($VIRTUAL_ENV)
elif [ -n "$VIRTUAL_ENV" ] && [ -f "$VIRTUAL_ENV/bin/pytest" ]; then
    PYTEST_CMD=("$VIRTUAL_ENV/bin/pytest")
elif [ -n "$VIRTUAL_ENV" ] && [ -f "$VIRTUAL_ENV/Scripts/pytest.exe" ]; then
    PYTEST_CMD=("$VIRTUAL_ENV/Scripts/pytest.exe")
elif [ -n "$VIRTUAL_ENV" ] && [ -f "$VIRTUAL_ENV/Scripts/pytest" ]; then
    PYTEST_CMD=("$VIRTUAL_ENV/Scripts/pytest")
# 4. Check system/environment PATH
elif command -v pytest &> /dev/null; then
    PYTEST_CMD=("pytest")
elif command -v python3 &> /dev/null && python3 -m pytest --version &> /dev/null; then
    PYTEST_CMD=("python3" "-m" "pytest")
elif command -v python &> /dev/null && python -m pytest --version &> /dev/null; then
    PYTEST_CMD=("python" "-m" "pytest")
elif command -v py &> /dev/null && py -m pytest --version &> /dev/null; then
    PYTEST_CMD=("py" "-m" "pytest")
else
    echo "======================================================================"
    echo "❌ Python virtual environment or pytest not found!"
    echo "======================================================================"
    echo "Searched locations:"
    echo "  - ${DIR}/backend/venv/bin/pytest (macOS / Linux)"
    echo "  - ${DIR}/backend/venv/Scripts/pytest.exe (Windows)"
    echo "  - Active \$VIRTUAL_ENV or system PATH"
    echo ""
    echo "To set up the environment in Windows Git Bash:"
    echo "  1. cd backend"
    echo "  2. python -m venv venv"
    echo "  3. source venv/Scripts/activate"
    echo "  4. pip install -r requirements.txt"
    echo "  5. python -m playwright install chromium"
    echo ""
    echo "Then re-run: ./run_e2e.sh"
    echo "======================================================================"
    exit 1
fi

# Locate python binary to check if playwright is installed
PYTHON_BIN=""
if [ -f "${DIR}/backend/venv/bin/python" ]; then
    PYTHON_BIN="${DIR}/backend/venv/bin/python"
elif [ -f "${DIR}/backend/venv/Scripts/python.exe" ]; then
    PYTHON_BIN="${DIR}/backend/venv/Scripts/python.exe"
elif [ -n "$VIRTUAL_ENV" ] && [ -f "$VIRTUAL_ENV/Scripts/python.exe" ]; then
    PYTHON_BIN="$VIRTUAL_ENV/Scripts/python.exe"
elif [ -n "$VIRTUAL_ENV" ] && [ -f "$VIRTUAL_ENV/bin/python" ]; then
    PYTHON_BIN="$VIRTUAL_ENV/bin/python"
elif command -v python &> /dev/null; then
    PYTHON_BIN="python"
elif command -v python3 &> /dev/null; then
    PYTHON_BIN="python3"
fi

if [ -n "$PYTHON_BIN" ]; then
    if ! "$PYTHON_BIN" -c "import playwright" &> /dev/null; then
        echo "======================================================================"
        echo "⚠️  The 'playwright' package is not installed in your Python environment."
        echo ""
        echo "Please install it with:"
        echo "  pip install playwright pytest-playwright"
        echo "  python -m playwright install chromium"
        echo "======================================================================"
        exit 1
    fi
fi

HEADED_FLAG="--headed"
SLOWMO_FLAG="--slowmo 1000"
EXTRA_ARGS=()

while [ $# -gt 0 ]; do
    case "$1" in
        --headless)
            HEADED_FLAG=""
            SLOWMO_FLAG=""
            shift
            ;;
        --fast)
            HEADED_FLAG="--headed"
            SLOWMO_FLAG=""
            shift
            ;;
        --slowmo)
            if [ -n "$2" ] && [[ "$2" =~ ^[0-9]+$ ]]; then
                SLOWMO_FLAG="--slowmo $2"
                shift 2
            else
                SLOWMO_FLAG="--slowmo 1000"
                shift
            fi
            ;;
        --slowmo=*)
            SLOWMO_VAL="${1#*=}"
            SLOWMO_FLAG="--slowmo $SLOWMO_VAL"
            shift
            ;;
        test_01|test_01*|*auth_and_rbac*)
            EXTRA_ARGS+=("${DIR}/tests_e2e/test_01_auth_and_rbac.py")
            shift
            ;;
        test_02|test_02*|*assets_and_remediation*)
            EXTRA_ARGS+=("${DIR}/tests_e2e/test_02_assets_and_remediation.py")
            shift
            ;;
        test_03|test_03*|*alerts_lifecycle*)
            EXTRA_ARGS+=("${DIR}/tests_e2e/test_03_alerts_lifecycle.py")
            shift
            ;;
        test_04|test_04*|*misp_threat_intel*)
            EXTRA_ARGS+=("${DIR}/tests_e2e/test_04_misp_threat_intel.py")
            shift
            ;;
        test_05|test_05*|*admin_governance*)
            EXTRA_ARGS+=("${DIR}/tests_e2e/test_05_admin_governance.py")
            shift
            ;;
        *)
            EXTRA_ARGS+=("$1")
            shift
            ;;
    esac
done

if [ ${#EXTRA_ARGS[@]} -eq 0 ]; then
    EXTRA_ARGS+=("${DIR}/tests_e2e")
fi

echo "======================================================================"
echo "🚀 Launching Automated Browser Integration Test Suite"
echo "Target Base URL: $BASE_URL"
if [ -n "$HEADED_FLAG" ]; then
    echo "Mode: Visible Browser on Screen (${SLOWMO_FLAG:-no slowdown})"
else
    echo "Mode: Headless (Background)"
fi
echo "Target: ${EXTRA_ARGS[*]}"
echo "======================================================================"

E2E_BASE_URL="$BASE_URL" "${PYTEST_CMD[@]}" "${EXTRA_ARGS[@]}" $HEADED_FLAG $SLOWMO_FLAG -v -s --tb=short
