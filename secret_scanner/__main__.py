"""Entry point for running secret_scanner as a module.

This file is what Python executes when you run:
    python -m secret_scanner [args]

The -m flag tells Python to find a package named "secret_scanner" and
run its __main__.py file. This is the standard way to make a Python
package executable — it's how tools like pip (python -m pip) and pytest
(python -m pytest) work.

This file is intentionally thin — it just calls cli.main(). All the
real logic lives in cli.py, scanner.py, and the subpackages.
"""

from .cli import main

main()
