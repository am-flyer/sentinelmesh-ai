import sys
import os

# Resolve the project root directory
root_dir = os.path.dirname(os.path.abspath(__file__))

# Remove root_dir from sys.path to prevent local 'agents' folder from shadowing the third-party 'agents' package
sys.path = [p for p in sys.path if os.path.abspath(p) != root_dir]
# Also remove empty/dot paths if they refer to the root
sys.path = [p for p in sys.path if p not in ("", ".")]
