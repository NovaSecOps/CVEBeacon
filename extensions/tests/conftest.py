import sys
from pathlib import Path

# Source test convenience only; installed-package smoke tests use another cwd.
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
