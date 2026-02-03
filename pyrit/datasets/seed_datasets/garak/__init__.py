# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
GARAK probe integration for PyRIT.

This package provides integration between GARAK probes and PyRIT's seed dataset
system. GARAK (Generative AI Red-teaming and Assessment Kit) is a framework
for testing vulnerabilities in language models.

The integration allows GARAK probes to be used with PyRIT's attack and
orchestration systems by converting them to PyRIT's SeedDataset format.

Main components:
- probe_loader: GarakProbeLoader class that wraps GARAK probes as SeedDatasetProviders
- probes/: Directory containing adapted GARAK probe implementations

Example usage:
    >>> from pyrit.datasets.seed_datasets.garak import (
    ...     GarakProbeLoader,
    ...     _GarakApiKeyGetKeyDataset,
    ...     _GarakApiKeyCompleteKeyDataset,
    ... )
    >>>
    >>> # Using pre-defined loaders
    >>> loader = _GarakApiKeyGetKeyDataset()
    >>> dataset = await loader.fetch_dataset()
    >>>
    >>> # Or using the generic loader with any probe class
    >>> from pyrit.datasets.seed_datasets.garak.probes.apikey import GetKey
    >>> loader = GarakProbeLoader(probe_class=GetKey)
    >>> dataset = await loader.fetch_dataset()
"""

from pyrit.datasets.seed_datasets.garak.probe_loader import (
    GarakProbeLoader,
    _GarakApiKeyCompleteKeyDataset,
    _GarakApiKeyGetKeyDataset,
    _GarakExploitationJinjaDataset,
    _GarakExploitationSQLiEchoDataset,
    _GarakExploitationSQLiSystemDataset,
    create_probe_dataset_loaders,
    discover_probe_classes,
)

__all__ = [
    "GarakProbeLoader",
    "_GarakApiKeyGetKeyDataset",
    "_GarakApiKeyCompleteKeyDataset",
    "_GarakExploitationJinjaDataset",
    "_GarakExploitationSQLiEchoDataset",
    "_GarakExploitationSQLiSystemDataset",
    "discover_probe_classes",
    "create_probe_dataset_loaders",
]
