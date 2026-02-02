# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
GARAK probe implementations adapted for PyRIT.

This package contains probe classes that generate prompts designed to test
specific vulnerabilities in language models. Each probe inherits from the
base Probe class and implements the _generate_prompts method.

Available probes:
- apikey.GetKey: Tests if models will generate API keys
- apikey.CompleteKey: Tests if models will complete partial API keys

Adding new probes:
1. Create a new module in this directory (e.g., myprobe.py)
2. Import and subclass the Probe base class
3. Implement the _generate_prompts method
4. Set class attributes: goal, description, tags, primary_detector
5. The probe will be auto-discovered by discover_probe_classes()

Example:
    >>> from pyrit.datasets.seed_datasets.garak.probes.base import Probe
    >>>
    >>> class MyProbe(Probe):
    ...     goal = "test something specific"
    ...     description = "Tests for a specific vulnerability"
    ...     tags = ["security"]
    ...     primary_detector = "mydetector.MyDetector"
    ...
    ...     def _generate_prompts(self):
    ...         return ["prompt 1", "prompt 2"]
"""

from pyrit.datasets.seed_datasets.garak.probes.apikey import CompleteKey, GetKey
from pyrit.datasets.seed_datasets.garak.probes.base import Probe, ProbeAttempt

__all__ = [
    "Probe",
    "ProbeAttempt",
    "GetKey",
    "CompleteKey",
]
