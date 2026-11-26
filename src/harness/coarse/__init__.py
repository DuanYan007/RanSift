"""Watch-set driven process-tree construction over decoupled slice facts."""

from .denoise import filter_csv_by_tree, load_tree_intervals
from .events import EventRecord, normalize_event
from .fact_stream import EventCountSlicer, SliceFactExtractor, iter_csv_slice_envelopes
from .models import ProcessFact, ProcessTreeNode, ProcessTreeOutput, SliceEnvelope, SliceMeta
from .spawn_reducer import SpawnReducer
from .watch_tree import WatchTreeBuilder, build_tree_from_csv

__all__ = [
    "EventCountSlicer",
    "filter_csv_by_tree",
    "EventRecord",
    "normalize_event",
    "load_tree_intervals",
    "ProcessFact",
    "ProcessTreeNode",
    "ProcessTreeOutput",
    "SliceEnvelope",
    "SliceFactExtractor",
    "SliceMeta",
    "SpawnReducer",
    "WatchTreeBuilder",
    "build_tree_from_csv",
    "iter_csv_slice_envelopes",
]
