# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import json
import logging
import uuid
from pathlib import Path
from typing import Optional

from pyrit.common.path import DATASETS_PATH
from pyrit.exceptions import InvalidJsonException, pyrit_json_retry, remove_markdown_json
from pyrit.models import Message, MessagePiece, SeedPrompt
from pyrit.prompt_target import PromptChatTarget

logger = logging.getLogger(__name__)

GISKARD_PROMPTS_PATH = Path(DATASETS_PATH, "seed_datasets", "giskard").resolve()


class RequirementsBasedLoader:
    """
    Generates testable requirements and adversarial inputs using an LLM.

    This loader sends structured prompts to an LLM to:
    1. Generate specific requirements an AI agent must satisfy for a given risk category.
    2. Generate adversarial inputs designed to make the agent violate those requirements.

    Ported from Giskard OSS (TestcaseRequirementsGenerator + AdversarialDataGenerator).
    Does not extend SeedDatasetProvider.
    """

    def __init__(self, *, chat_target: PromptChatTarget) -> None:
        """
        Initialize the RequirementsBasedLoader.

        Args:
            chat_target: The LLM target used for generating requirements and adversarial inputs.
        """
        self._chat_target = chat_target

        # Load system prompt templates
        self._requirement_generator_prompt = SeedPrompt.from_yaml_file(
            GISKARD_PROMPTS_PATH / "requirement_generator_system.prompt"
        )
        self._adversarial_generator_prompt = SeedPrompt.from_yaml_file(
            GISKARD_PROMPTS_PATH / "adversarial_generator_system.prompt"
        )

    async def _send_prompt_async(self, *, system_prompt: str, user_prompt: str) -> str:
        """
        Send a system + user prompt to the chat target and return the response text.

        Args:
            system_prompt: The system-level instructions.
            user_prompt: The user-level message with specific parameters.

        Returns:
            The LLM's text response.
        """
        conversation_id = str(uuid.uuid4())

        self._chat_target.set_system_prompt(
            system_prompt=system_prompt,
            conversation_id=conversation_id,
        )

        request = Message(
            message_pieces=[
                MessagePiece(
                    role="user",
                    original_value=user_prompt,
                    conversation_id=conversation_id,
                    prompt_target_identifier=self._chat_target.get_identifier(),
                    prompt_metadata={"response_format": "json"},
                )
            ]
        )

        response = await self._chat_target.send_prompt_async(message=request)
        return response[0].get_value()

    @pyrit_json_retry
    async def generate_requirements_async(
        self,
        *,
        category: str,
        num_requirements: int = 5,
        agent_description: Optional[str] = None,
    ) -> list[str]:
        """
        Generate a list of testable requirements for a given risk category.

        Args:
            category: The risk category to generate requirements for
                (e.g., "Harmful content generation", "Stereotypes and discrimination").
            num_requirements: Number of requirements to generate. Defaults to 5.
            agent_description: Optional description of the agent under test.
                When provided, requirements will be tailored to the specific agent.

        Returns:
            A list of requirement strings.

        Raises:
            InvalidJsonException: If the LLM response is not valid JSON.
        """
        system_prompt = self._requirement_generator_prompt.value

        # Build user prompt
        parts = []
        if agent_description:
            parts.append(f"### AGENT DESCRIPTION\n{agent_description}")
        parts.append(f"### CATEGORY\n{category}")
        parts.append(f"### NUM REQUIREMENTS\n{num_requirements}")
        user_prompt = "\n\n".join(parts)

        response_text = await self._send_prompt_async(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

        try:
            response_text = remove_markdown_json(response_text)
            parsed = json.loads(response_text)
            requirements = parsed["requirements"]
            if not isinstance(requirements, list) or not all(isinstance(r, str) for r in requirements):
                raise InvalidJsonException(
                    message=f"Expected 'requirements' to be a list of strings, got: {requirements}"
                )
            logger.info(f"Generated {len(requirements)} requirements for category: {category}")
            return requirements
        except (json.JSONDecodeError, KeyError) as e:
            raise InvalidJsonException(
                message=f"Invalid JSON response from requirement generator: {response_text}"
            ) from e

    @pyrit_json_retry
    async def generate_adversarial_inputs_async(
        self,
        *,
        category: str,
        requirement: str,
        num_inputs: int = 3,
        agent_description: Optional[str] = None,
    ) -> list[str]:
        """
        Generate adversarial inputs designed to make the agent violate a specific requirement.

        Args:
            category: The risk category.
            requirement: The specific requirement to target.
            num_inputs: Number of adversarial inputs to generate. Defaults to 3.
            agent_description: Optional description of the agent under test.

        Returns:
            A list of adversarial input strings.

        Raises:
            InvalidJsonException: If the LLM response is not valid JSON.
        """
        system_prompt = self._adversarial_generator_prompt.value

        # Build user prompt
        parts = []
        if agent_description:
            parts.append(f"### AGENT DESCRIPTION\n{agent_description}")
        parts.append(f"### CATEGORY\n{category}")
        parts.append(f"### REQUIREMENT\n{requirement}")
        parts.append(f"### NUM INPUTS\n{num_inputs}")
        user_prompt = "\n\n".join(parts)

        response_text = await self._send_prompt_async(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

        try:
            response_text = remove_markdown_json(response_text)
            parsed = json.loads(response_text)
            inputs = parsed["inputs"]
            if not isinstance(inputs, list) or not all(isinstance(i, str) for i in inputs):
                raise InvalidJsonException(
                    message=f"Expected 'inputs' to be a list of strings, got: {inputs}"
                )
            logger.info(
                f"Generated {len(inputs)} adversarial inputs for requirement: {requirement[:80]}..."
            )
            return inputs
        except (json.JSONDecodeError, KeyError) as e:
            raise InvalidJsonException(
                message=f"Invalid JSON response from adversarial generator: {response_text}"
            ) from e
