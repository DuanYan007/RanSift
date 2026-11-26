"""Verify two-level grouping, exact provenance and catalog compatibility."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from harness.behavior.blocks import build_process_behavior_blocks
from harness.behavior.catalog import build_behavior_catalog
from harness.behavior.catalog_store import CatalogEvidenceStore
from harness.behavior.catalog_streaming_tools import StreamingCatalogEvidenceTools
from harness.behavior.hierarchical_fragments import build_hierarchical_fragments
from harness.tasks.behavior import behavior_event_from_dict


def event(offset, path, operation='WriteFile', *, pid=42, node='node_1', timestamp=None, result='SUCCESS'):
    return {'order': {'filtered': offset, 'source': f'ev_{offset:08d}'},
            'time': {'timestamp': offset/10 if timestamp is None else timestamp},
            'action': {'operation': operation, 'category': 'file', 'result': result},
            'target': {'path': path, 'normalized_path': path.casefold(), 'namespace': 'users',
                       'extension': Path(path.replace('\\', '/')).suffix.lstrip('.')},
            'detail': {}, 'process_context': {'pid': pid, 'node_id': node, 'process_name': 'demo.exe'}}


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def offsets(block):
    if 'source_offsets' in block:
        return block['source_offsets']
    return [n for start, end in block['source_offset_ranges'] for n in range(start, end+1)]


class HierarchicalFragmentTests(unittest.TestCase):
    def build(self, root, events, **kwargs):
        trace = root/'events.jsonl'
        trace.write_text(''.join(json.dumps(e)+'\n' for e in events))
        catalog = build_behavior_catalog(trace_path=trace, phase_blocks_path=root/'phase.jsonl',
                                         checkpoints_path=root/'checkpoints.json')
        hierarchy = build_hierarchical_fragments(trace, root/'micro.jsonl', root/'macro.jsonl', **kwargs)
        catalog['hierarchical_fragments'] = hierarchy
        (root/'catalog.json').write_text(json.dumps(catalog))
        store = CatalogEvidenceStore(trace, root/'catalog.json', root/'phase.jsonl', root/'checkpoints.json')
        return hierarchy, store

    def test_two_targets_become_two_micro_children_of_one_macro(self):
        events = [event(0, r'C:\Users\demo\a.txt', 'ReadFile'),
                  event(1, r'C:\Users\demo\a.txt'),
                  event(2, r'C:\Users\demo\b.txt', 'ReadFile'),
                  event(3, r'C:\Users\demo\b.txt', result='ACCESS DENIED')]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d);hierarchy, store = self.build(root, events)
            micro = store.blocks_payload['micro_blocks'];macro = store.blocks_payload['macro_blocks']
            self.assertEqual([offsets(b) for b in micro], [[0, 1], [2, 3]])
            self.assertEqual(len(macro), 1)
            self.assertEqual(macro[0]['child_block_ids'], [b['block_id'] for b in micro])
            self.assertTrue(all(b['parent_block_id'] == macro[0]['block_id'] for b in micro))
            self.assertEqual(macro[0]['result_counts']['ACCESS DENIED'], 1)
            tools = StreamingCatalogEvidenceTools(store)
            self.assertEqual(tools.list_blocks(level='micro').returned_count, 2)
            self.assertEqual(tools.list_blocks(level='macro').returned_count, 1)
            expanded = tools.get_block_events(macro[0]['block_id'], representative_only=False, limit=20)
            self.assertEqual([r.offset for r in expanded.evidence_refs], [0, 1, 2, 3])
            self.assertEqual(expanded.matched_count, 4)
            self.assertEqual(set(store.query_surface()['block_kinds']), {'micro', 'macro'})
            neighbors = tools.neighbor_blocks(micro[0]['block_id'])
            self.assertEqual(neighbors.returned_count, 2)
            self.assertTrue(all(b['level'] == 'micro' for b in neighbors.blocks))
            target = tools.trace_target(r'C:\Users\demo\a.txt', prefix=False)
            self.assertTrue(target.blocks)
            self.assertTrue(all(b['level'] == 'macro' for b in target.blocks))

    def test_interleaved_processes_and_reused_pid_do_not_mix(self):
        events = [event(0, r'C:\Users\demo\a.txt'),
                  event(1, r'C:\Users\demo\a.txt', node='node_2'),
                  event(2, r'C:\Users\demo\a.txt'),
                  event(3, r'C:\Users\demo\a.txt', node='node_2')]
        with tempfile.TemporaryDirectory() as d:
            _, store = self.build(Path(d), events)
            macro = store.blocks_payload['macro_blocks']
            self.assertEqual(sorted(offsets(b) for b in macro), [[0, 2], [1, 3]])
            tools = StreamingCatalogEvidenceTools(store)
            first = next(b for b in macro if offsets(b) == [0, 2])
            expanded = tools.get_block_events(first['block_id'], representative_only=False, limit=20)
            self.assertEqual([r.offset for r in expanded.evidence_refs], [0, 2])

    def test_matches_existing_two_level_rules_below_cap(self):
        paths = [r'C:\Users\demo\a.txt', r'C:\Users\demo\a.txt',
                 r'C:\Users\demo\b.txt', r'C:\Users\demo\b.txt',
                 r'C:\Users\demo\c.docx', r'C:\Users\demo\c.docx']
        events = [event(i, p, 'ReadFile' if i%2 == 0 else 'WriteFile') for i, p in enumerate(paths)]
        reference = build_process_behavior_blocks(behavior_event_from_dict(e) for e in events)
        with tempfile.TemporaryDirectory() as d:
            _, store = self.build(Path(d), events)
            for level in ('micro', 'macro'):
                old = getattr(reference, level+'_blocks')
                new = store.blocks_payload[level+'_blocks']
                self.assertEqual(sorted(tuple(b.source_offsets) for b in old), sorted(tuple(offsets(b)) for b in new))

    def test_time_order_and_scope_boundaries(self):
        events = [event(0, r'C:\Users\demo\a.txt', timestamp=0),
                  event(1, r'C:\Users\demo\a.txt', timestamp=3),
                  event(2, r'C:\Users\demo\a.txt', timestamp=14),
                  event(3, r'C:\Users\demo\b.docx', timestamp=14.1)]
        with tempfile.TemporaryDirectory() as d:
            _, store = self.build(Path(d), events)
            self.assertEqual(len(store.blocks_payload['micro_blocks']), 4)
            self.assertEqual(sorted(offsets(b) for b in store.blocks_payload['macro_blocks']), [[0, 1], [2], [3]])
        events = [event(i, r'C:\Users\demo\a.txt' if i in (0, 26) else r'C:\Users\demo\b.txt',
                        node='node_1' if i in (0, 26) else 'node_2', timestamp=i/100) for i in range(27)]
        with tempfile.TemporaryDirectory() as d:
            _, store = self.build(Path(d), events)
            first_process = [b for b in store.blocks_payload['micro_blocks'] if b['process_instance']['node_id']=='node_1']
            self.assertEqual(len(first_process), 2)

    def test_cap_splits_without_dropping_events(self):
        events = [event(i, r'C:\Users\demo\a.txt') for i in range(12)]
        with tempfile.TemporaryDirectory() as d:
            hierarchy, store = self.build(Path(d), events, event_cap=4)
            for level in ('micro', 'macro'):
                blocks = store.blocks_payload[level+'_blocks']
                self.assertEqual(len(blocks), 3)
                self.assertEqual(sorted(n for b in blocks for n in offsets(b)), list(range(12)))
                self.assertTrue(all(b['event_count'] <= 4 for b in blocks))
                self.assertEqual(hierarchy[level]['event_count'], 12)

    def test_large_fragment_expansion_uses_exact_ranges(self):
        events = [event(i, r'C:\Users\demo\a.txt', timestamp=i/1000) for i in range(600)]
        with tempfile.TemporaryDirectory() as d:
            _, store = self.build(Path(d), events)
            block = store.blocks_payload['macro_blocks'][0]
            self.assertNotIn('source_offsets', block)
            result = StreamingCatalogEvidenceTools(store).get_block_events(block['block_id'], representative_only=False, limit=3)
            self.assertEqual(result.matched_count, 600)
            self.assertEqual([r.offset for r in result.evidence_refs], [0, 1, 2])

    def test_modified_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d);_, store = self.build(root, [event(0, r'C:\Users\demo\a.txt')])
            with (root/'micro.jsonl').open('a') as f:f.write('\n')
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):_ = store.blocks_payload

    def test_broken_parent_reference_is_rejected_even_with_updated_digest(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d);_, store = self.build(root, [event(0, r'C:\Users\demo\a.txt')])
            child = rows(root/'micro.jsonl')[0];child['parent_block_id']='missing'
            (root/'micro.jsonl').write_text(json.dumps(child)+'\n')
            catalog = json.loads((root/'catalog.json').read_text())
            catalog['hierarchical_fragments']['micro']['sha256'] = hashlib.sha256((root/'micro.jsonl').read_bytes()).hexdigest()
            (root/'catalog.json').write_text(json.dumps(catalog))
            with self.assertRaisesRegex(ValueError, 'parent or process mismatch'):_ = store.blocks_payload

    def test_legacy_phase_only_catalog_remains_queryable(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d);self.build(root, [event(0, r'C:\Users\demo\a.txt')])
            catalog = json.loads((root/'catalog.json').read_text());catalog.pop('hierarchical_fragments')
            (root/'catalog.json').write_text(json.dumps(catalog))
            store = CatalogEvidenceStore(root/'events.jsonl', root/'catalog.json', root/'phase.jsonl', root/'checkpoints.json')
            tools = StreamingCatalogEvidenceTools(store)
            self.assertEqual(tools.list_blocks(level='micro').returned_count, 1)
            self.assertEqual(tools.list_blocks(level='macro').returned_count, 1)
            self.assertEqual(store.blocks_payload['macro_blocks'][0]['level'], 'phase')


if __name__ == '__main__':
    unittest.main()
