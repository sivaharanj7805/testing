# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import logging
from pathlib import Path
from typing import Optional, Sequence

from pyrit.common.path import DATASETS_PATH
from pyrit.identifiers import ScorerIdentifier
from pyrit.models import MessagePiece, Score, SeedPrompt
from pyrit.prompt_target import PromptChatTarget
from pyrit.score.scorer_prompt_validator import ScorerPromptValidator
from pyrit.score.true_false.true_false_score_aggregator import (
    TrueFalseAggregatorFunc,
    TrueFalseScoreAggregator,
)
from pyrit.score.true_false.true_false_scorer import TrueFalseScorer

logger = logging.getLogger(__name__)

GISKARD_PROMPTS_PATH = Path(DATASETS_PATH, "seed_datasets", "giskard").resolve()


class GiskardRequirementEvaluator(TrueFalseScorer):
    """
    Evaluates whether an AI agent's response violates a set of requirements.

    This scorer is ported from Giskard OSS's RequirementEvaluator. It takes a list of
    requirements and evaluates each response against them using an LLM judge.

    Score values:
    - "true" = A requirement violation was detected.
    - "false" = All requirements were satisfied (no violation).
    """

    _default_validator: ScorerPromptValidator = ScorerPromptValidator(
        supported_data_types=["text"],
    )

    def __init__(
        self,
        *,
        chat_target: PromptChatTarget,
        requirements: Sequence[str],
        agent_description: Optional[str] = None,
        validator: Optional[ScorerPromptValidator] = None,
        score_aggregator: TrueFalseAggregatorFunc = TrueFalseScoreAggregator.OR,
    ) -> None:
        """
        Initialize the GiskardRequirementEvaluator.

        Args:
            chat_target: The LLM target used for evaluation.
            requirements: List of requirement strings to evaluate against.
            agent_description: Optional description of the agent being evaluated.
                When provided, gives the evaluator LLM context about the agent's purpose.
            validator: Custom validator. Defaults to text-only support.
            score_aggregator: The aggregator function for multi-piece messages.
                Defaults to TrueFalseScoreAggregator.OR.

        Raises:
            ValueError: If requirements list is empty.
        """
        super().__init__(
            validator=validator or self._default_validator,
            score_aggregator=score_aggregator,
        )

        if not requirements:
            raise ValueError("At least one requirement must be provided.")

        self._prompt_target = chat_target
        self._requirements = list(requirements)
        self._agent_description = agent_description

        # Format requirements as bulleted list for the system prompt
        requirements_text = "\n".join(f"- {r}" for r in self._requirements)

        # Load and render the system prompt template
        evaluator_template = SeedPrompt.from_yaml_file(
            GISKARD_PROMPTS_PATH / "requirement_evaluator_system.prompt"
        )

        self._system_prompt = evaluator_template.render_template_value(
            requirements=requirements_text,
        )

        # If agent description is provided, prepend it to the system prompt
        if self._agent_description:
            self._system_prompt = (
                f"### AGENT DESCRIPTION\n{self._agent_description}\n\n{self._system_prompt}"
            )

        self._score_category = "giskard_requirement_violation"

    def _build_identifier(self) -> ScorerIdentifier:
        """Build the scorer identifier."""
        return self._create_identifier(
            system_prompt_template=self._system_prompt,
            user_prompt_template="objective: {objective}\nresponse: {response}",
            prompt_target=self._prompt_target,
            score_aggregator=self._score_aggregator.__name__,
            scorer_specific_params={
                "num_requirements": len(self._requirements),
                "has_agent_description": self._agent_description is not None,
            },
        )

    async def _score_piece_async(
        self, message_piece: MessagePiece, *, objective: Optional[str] = None
    ) -> list[Score]:
        """
        Evaluate a single message piece against the configured requirements.

        Args:
            message_piece: The message piece containing the agent's response text.
            objective: The original user input / objective that prompted the response.

        Returns:
            A list containing a single Score object.
            score_value="true" means a violation was detected.
            score_value="false" means all requirements were satisfied.
        """
        scoring_value = f"objective: {objective}\nresponse: {message_piece.converted_value}"

        unvalidated_score = await self._score_value_with_llm(
            prompt_target=self._prompt_target,
            system_prompt=self._system_prompt,
            message_value=scoring_value,
            message_data_type="text",
            scored_prompt_id=message_piece.id,
            category=self._score_category,
            objective=objective,
            attack_identifier=message_piece.attack_identifier,
        )

        score = unvalidated_score.to_score(
            score_value=unvalidated_score.raw_score_value,
            score_type="true_false",
        )
        return [score]
