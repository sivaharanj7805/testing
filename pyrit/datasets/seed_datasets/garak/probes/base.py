# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Base class for GARAK probes adapted for PyRIT.

This module provides the foundation for porting GARAK probes to work with PyRIT's
seed dataset system. GARAK probes generate prompts designed to test specific
vulnerabilities in language models.

The Probe base class is designed to be a minimal, self-contained implementation
that does not import from the original GARAK library. Users can manually copy
GARAK probe files into the probes directory and have them work with PyRIT.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)


@dataclass
class ProbeAttempt:
    """
    Represents a single probe attempt with its prompt and metadata.

    This is a simplified version of GARAK's Attempt class, containing only
    the essential fields needed for integration with PyRIT.
    """

    prompt: str
    """The prompt text to send to the target model."""

    goal: str = ""
    """Description of what this probe attempt is trying to achieve."""

    notes: Dict[str, Any] = field(default_factory=dict)
    """Additional metadata about the attempt, including triggers for detection."""

    probe_classname: str = ""
    """The full class name of the probe that generated this attempt."""

    tags: List[str] = field(default_factory=list)
    """Taxonomy tags for categorizing the probe."""


class Probe(ABC):
    """
    Abstract base class for GARAK-style probes.

    This class provides the structure for probes that generate prompts designed
    to test specific vulnerabilities in language models. Subclasses must implement
    the `_generate_prompts` method to produce a list of prompts.

    The design mirrors GARAK's probe architecture while being self-contained
    and compatible with PyRIT's seed dataset system.

    Attributes:
        probename: Auto-generated name based on class name.
        goal: Imperative description of what the probe is trying to achieve.
        description: Detailed description of the probe's purpose.
        tags: MISP-format taxonomy tags for categorization.
        primary_detector: The recommended detector/scorer for this probe.
        active: Whether the probe is included in default runs.
    """

    # Class-level attributes that subclasses should override
    goal: str = ""
    """Imperative description of the probe's goal (e.g., 'make the model leak API keys')."""

    description: str = ""
    """Detailed description of the probe."""

    tags: List[str] = field(default_factory=list) if False else []
    """Taxonomy tags for categorization."""

    primary_detector: str = ""
    """The recommended detector/scorer class name for this probe."""

    active: bool = True
    """Whether the probe is included in default execution."""

    # Default parameters that can be overridden
    DEFAULT_PARAMS: Dict[str, Any] = {}
    """Default configuration parameters for the probe."""

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the probe.

        Args:
            config: Optional configuration dictionary to override defaults.
        """
        self.probename = self.__class__.__name__
        self._config = {**self.DEFAULT_PARAMS, **(config or {})}
        self.prompts: List[str] = []

        # Initialize prompts by calling the generation method
        self._setup()

    def _setup(self) -> None:
        """
        Set up the probe by generating prompts.

        This method is called during initialization. Subclasses can override
        this to customize initialization behavior.
        """
        self.prompts = self._generate_prompts()

    @abstractmethod
    def _generate_prompts(self) -> List[str]:
        """
        Generate the list of prompts for this probe.

        This is the main method that subclasses must implement. It should
        return a list of prompt strings that will be used to test the target model.

        Returns:
            List of prompt strings.
        """
        pass

    def get_attempts(self) -> List[ProbeAttempt]:
        """
        Convert generated prompts into ProbeAttempt objects.

        Returns:
            List of ProbeAttempt objects with full metadata.
        """
        attempts = []
        for prompt in self.prompts:
            attempt = ProbeAttempt(
                prompt=prompt,
                goal=self.goal,
                probe_classname=f"{self.__class__.__module__}.{self.__class__.__name__}",
                tags=self.tags.copy() if self.tags else [],
                notes=self._get_attempt_notes(prompt),
            )
            attempts.append(attempt)
        return attempts

    def _get_attempt_notes(self, prompt: str) -> Dict[str, Any]:
        """
        Generate notes/metadata for a specific prompt.

        Subclasses can override this to add probe-specific metadata
        such as triggers for detection.

        Args:
            prompt: The prompt string.

        Returns:
            Dictionary of notes/metadata.
        """
        return {}

    def get_prompts(self) -> List[str]:
        """
        Get the list of generated prompts.

        Returns:
            List of prompt strings.
        """
        return self.prompts.copy()

    @property
    def harm_categories(self) -> List[str]:
        """
        Extract harm categories from tags.

        Returns:
            List of harm category strings derived from tags.
        """
        categories = []
        for tag in self.tags:
            # Extract category from MISP-style tags (e.g., "avid-effect:security:S0403")
            if ":" in tag:
                parts = tag.split(":")
                if len(parts) >= 2:
                    categories.append(parts[1])
        return list(set(categories)) if categories else ["security"]
