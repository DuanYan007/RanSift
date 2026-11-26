"""Streaming two-level fragments using the established micro/macro rules."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import hashlib
import json

from .blocks import (
    DEFAULT_MICRO_TIME_GAP_S, DEFAULT_MICRO_ORDER_GAP,
    DEFAULT_MACRO_TIME_GAP_S, DEFAULT_MACRO_ORDER_GAP,
    block_from_atoms, block_from_children, compatible_micro, compatible_macro,
    event_to_atom,
)
from harness.tasks.behavior import behavior_event_from_dict

SCHEMA = 'behavior-fragment-hierarchy-v1'


def build_hierarchical_fragments(trace_path, micro_path, macro_path, *,
                                micro_time_gap_s=DEFAULT_MICRO_TIME_GAP_S,
                                micro_order_gap=DEFAULT_MICRO_ORDER_GAP,
                                macro_time_gap_s=DEFAULT_MACRO_TIME_GAP_S,
                                macro_order_gap=DEFAULT_MACRO_ORDER_GAP,
                                event_cap=2048):
    """Stream in filtered order; retain only open bounded groups per process.

    Each event belongs to exactly one micro and one macro. The existing
    compatibility predicates define grouping. The cap bounds each open micro
    and macro by event count; it is an additional split, never an event drop.
    """
    import math
    if (not math.isfinite(micro_time_gap_s) or not math.isfinite(macro_time_gap_s)
            or micro_time_gap_s < 0 or macro_time_gap_s < 0
            or type(micro_order_gap) is not int or micro_order_gap <= 0
            or type(macro_order_gap) is not int or macro_order_gap <= 0
            or type(event_cap) is not int or event_cap <= 0):
        raise ValueError('Invalid hierarchical fragment parameters')
    paths = {'micro': Path(micro_path), 'macro': Path(macro_path)}
    if len({Path(trace_path).resolve(), *(p.resolve() for p in paths.values())}) != 3:
        raise ValueError('Trace and fragment output paths must be distinct')
    for p in paths.values():
        p.parent.mkdir(parents=True, exist_ok=True)
    counts = Counter()
    events = Counter()
    kinds = {'micro': Counter(), 'macro': Counter()}
    open_micro = {}
    open_macro = {}
    macro_ids = {}
    macro_sizes = {}
    next_ids = {'micro': 1, 'macro': 1}

    def identifier(level):
        value = f'{level}_{next_ids[level]:08d}'
        next_ids[level] += 1
        return value

    with paths['micro'].open('w', encoding='utf-8') as micro_stream, \
         paths['macro'].open('w', encoding='utf-8') as macro_stream:
        streams = {'micro': micro_stream, 'macro': macro_stream}

        def emit(level, block, parent_id=None):
            payload = block.to_dict()
            payload['schema_version'] = SCHEMA
            if parent_id is not None:
                payload['parent_block_id'] = parent_id
            streams[level].write(json.dumps(payload, ensure_ascii=True, separators=(',', ':'))+'\n')
            counts[level] += 1
            events[level] += block.event_count
            kinds[level][block.behavior_kind] += 1

        def close_macro(key):
            children = open_macro.pop(key)
            emit('macro', block_from_children(macro_ids.pop(key), children))
            macro_sizes.pop(key)

        def close_micro(key):
            atoms = open_micro.pop(key)
            block = block_from_atoms(identifier('micro'), 'micro', atoms)
            children = open_macro.get(key)
            if children and (not compatible_macro(children[-1], block, macro_time_gap_s, macro_order_gap)
                             or macro_sizes[key] + block.event_count > event_cap):
                close_macro(key)
                children = None
            if children is None:
                open_macro[key] = children = []
                macro_ids[key] = identifier('macro')
                macro_sizes[key] = 0
            children.append(block)
            macro_sizes[key] += block.event_count
            emit('micro', block, macro_ids[key])

        event_count = 0
        with Path(trace_path).open(encoding='utf-8-sig') as stream:
            for line in stream:
                if not line.strip():
                    continue
                row = json.loads(line)
                if type(row['order']['filtered']) is not int or row['order']['filtered'] != event_count:
                    raise ValueError('Fragment input offsets must be contiguous from zero')
                atom = event_to_atom(behavior_event_from_dict(row))
                key = atom.process_instance.key
                current = open_micro.get(key)
                if current and (len(current) >= event_cap or not compatible_micro(
                        current, atom, micro_time_gap_s, micro_order_gap)):
                    close_micro(key)
                open_micro.setdefault(key, []).append(atom)
                event_count += 1
        for key in list(open_micro):
            close_micro(key)
        for key in list(open_macro):
            close_macro(key)
    if events['micro'] != event_count or events['macro'] != event_count:
        raise ValueError('Hierarchical fragment event conservation failed')
    result = {'schema_version': SCHEMA, 'event_count': event_count,
              'parameters': {'micro_time_gap_s': micro_time_gap_s, 'micro_order_gap': micro_order_gap,
                             'macro_time_gap_s': macro_time_gap_s, 'macro_order_gap': macro_order_gap,
                             'event_cap_per_fragment': event_cap},
              'integrity': {'event_count_matches_both_levels': True, 'status': 'pass'}}
    for level, path in paths.items():
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024*1024), b''):
                digest.update(chunk)
        result[level] = {'file': path.name, 'sha256': digest.hexdigest(),
                         'count': counts[level], 'event_count': events[level],
                         'by_behavior_kind': dict(kinds[level])}
    return result
