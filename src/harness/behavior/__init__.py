"""Second-layer behavior evidence models and parsers."""

from .evidence_auditor import (
    ClaimReview,
    EvidenceAuditorAgent,
    EvidenceAuditorConfig,
    EvidenceAuditorResult,
)
from .file_transformation import (
    FileTransformationAgent,
    FileTransformationConfig,
    FileTransformationResult,
)
from .file_discovery import (
    FileDiscoveryAgent,
    FileDiscoveryConfig,
    FileDiscoveryResult,
)
from .ransom_note import (
    RansomNoteAgent,
    RansomNoteConfig,
    RansomNoteResult,
)
from .recovery_impact import (
    RecoveryImpactAgent,
    RecoveryImpactConfig,
    RecoveryImpactResult,
)
from .process_execution import (
    ProcessExecutionAgent,
    ProcessExecutionConfig,
    ProcessExecutionResult,
)
from .registry_agent import (
    RegistryAgent,
    RegistryConfig,
    RegistryResult,
)
from .anti_analysis import (
    DynamicAntiAnalysisAgent,
    DynamicAntiAnalysisConfig,
    DynamicAntiAnalysisResult,
)
from .agent_prompts import (
    AgentPrompt,
)
from .context import (
    Claim,
    ClaimLedger,
    DryRunAgentRunner,
    DryRunResult,
    LLMContext,
    LLMContextBuilder,
    LoopState,
    MemoryFact,
    ToolCallPlan,
    WorkingMemory,
)
from .llm_loop import (
    JSONChatClient,
    OpenAICompatibleConfig,
    OpenAISDKCompatibleChatClient,
    LLMEvidenceAgentRunner,
    LLMEvidenceLoopConfig,
    LLMEvidenceLoopResult,
    context_to_messages,
)
from .llm_protocol import (
    parse_agent_response,
)
from .registry import (
    EvidenceLedger,
    ToolRegistry,
    ToolSpec,
)
from .evidence import (
    EvidenceRef,
    EvidenceStore,
    EvidenceTools,
    ToolResult,
)
from .blocks import (
    BehaviorAtom,
    BehaviorBlockSet,
    ProcessBehaviorBlock,
    ProcessInstance,
    build_process_behavior_blocks,
    event_to_atom,
)
from .models import (
    BehaviorAction,
    BehaviorDetail,
    BehaviorEvent,
    BehaviorOrder,
    BehaviorProcessContext,
    BehaviorSummary,
    BehaviorTarget,
    BehaviorTime,
)
from .parser import iter_behavior_events, parse_filtered_event, summarize_behavior_events
from .index import (
    BehaviorIndex,
    BehaviorIndexBuilder,
    build_behavior_index,
    materialize_behavior_artifacts,
    read_trace_events_at_offsets,
)

__all__ = [
    "ClaimReview",
    "EvidenceAuditorAgent",
    "EvidenceAuditorConfig",
    "EvidenceAuditorResult",
    "FileTransformationAgent",
    "FileTransformationConfig",
    "FileTransformationResult",
    "FileDiscoveryAgent",
    "FileDiscoveryConfig",
    "FileDiscoveryResult",
    "RansomNoteAgent",
    "RansomNoteConfig",
    "RansomNoteResult",
    "RecoveryImpactAgent",
    "RecoveryImpactConfig",
    "RecoveryImpactResult",
    "ProcessExecutionAgent",
    "ProcessExecutionConfig",
    "ProcessExecutionResult",
    "RegistryAgent",
    "RegistryConfig",
    "RegistryResult",
    "DynamicAntiAnalysisAgent",
    "DynamicAntiAnalysisConfig",
    "DynamicAntiAnalysisResult",
    "AgentPrompt",
    "Claim",
    "ClaimLedger",
    "DryRunAgentRunner",
    "DryRunResult",
    "LLMContext",
    "LLMContextBuilder",
    "LoopState",
    "MemoryFact",
    "ToolCallPlan",
    "WorkingMemory",
    "JSONChatClient",
    "OpenAICompatibleConfig",
    "OpenAISDKCompatibleChatClient",
    "LLMEvidenceAgentRunner",
    "LLMEvidenceLoopConfig",
    "LLMEvidenceLoopResult",
    "context_to_messages",
    "parse_agent_response",
    "ToolSpec",
    "ToolRegistry",
    "EvidenceLedger",
    "ToolResult",
    "EvidenceTools",
    "EvidenceStore",
    "EvidenceRef",
    "event_to_atom",
    "build_process_behavior_blocks",
    "ProcessInstance",
    "ProcessBehaviorBlock",
    "BehaviorBlockSet",
    "BehaviorAtom",
    "BehaviorAction",
    "BehaviorDetail",
    "BehaviorEvent",
    "BehaviorOrder",
    "BehaviorProcessContext",
    "BehaviorSummary",
    "BehaviorTarget",
    "BehaviorTime",
    "iter_behavior_events",
    "parse_filtered_event",
    "summarize_behavior_events",
    "read_trace_events_at_offsets",
    "materialize_behavior_artifacts",
    "build_behavior_index",
    "BehaviorIndexBuilder",
    "BehaviorIndex",
]
