import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from ransift.sample import SampleDirectory, SampleError, CSV_FIELDS

class SampleDirectoryTests(unittest.TestCase):
    def fixture(self, root):
        with (root/'raw_events.csv').open('w', newline='') as f:
            writer=csv.writer(f);writer.writerow(CSV_FIELDS)
            writer.writerow(['00:00:01','demo.exe',42,'ReadFile','C:/Demo/input.txt','SUCCESS','Length: 4'])
        tree={'root_nodes': ['node_1'], 'node_index': {'node_1': {'process': {'pid': 42}}}}
        (root/'process_tree.json').write_text(json.dumps(tree))
        e={'order': {'filtered': 0, 'source': 'ev_00000000'}, 'time': {'timestamp': 1},
           'action': {'operation': 'ReadFile'}, 'target': {'path': 'C:/Demo/input.txt'},
           'detail': {}, 'process_context': {'pid': 42, 'node_id': 'node_1'}}
        (root/'normalized_events.jsonl').write_text(json.dumps(e)+'\n')
        return e

    def test_standalone_read_only_and_no_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.fixture(root)
            before={p.name:p.read_bytes() for p in root.iterdir()}
            with patch('socket.socket', side_effect=AssertionError('Network forbidden')):
                result=SampleDirectory.open(root).validate(full=True)
            self.assertEqual(result['normalized_events_checked'],1)
            self.assertEqual(result['model_requests'],0)
            self.assertEqual(before,{p.name:p.read_bytes() for p in root.iterdir()})

    def test_missing_file_does_not_fall_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.fixture(root);(root/'process_tree.json').unlink()
            with self.assertRaises(SampleError):SampleDirectory.open(root)

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.fixture(root)
            (root/'raw_events.csv').rename(root/'other.csv')
            (root/'raw_events.csv').symlink_to(root/'other.csv')
            with self.assertRaises(SampleError):SampleDirectory.open(root)

    def test_process_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);e=self.fixture(root);e['process_context']['pid']=99
            (root/'normalized_events.jsonl').write_text(json.dumps(e)+'\n')
            with self.assertRaises(SampleError):SampleDirectory.open(root).validate(full=True)

    def test_full_validation_checks_later_offsets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);e=self.fixture(root);e['order']['filtered']=8
            with (root/'normalized_events.jsonl').open('a') as f:f.write(json.dumps(e)+'\n')
            with self.assertRaises(SampleError):SampleDirectory.open(root).validate(full=True)

    def test_error_does_not_echo_host_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.fixture(root);(root/'process_tree.json').write_text('{')
            with self.assertRaises(SampleError) as caught:SampleDirectory.open(root).validate()
            self.assertNotIn(tmp,str(caught.exception))

    def test_invalid_event_fields_rejected(self):
        for field, value in [('timestamp', None), ('timestamp', float('nan')),
                             ('timestamp', float('inf')), ('pid', None),
                             ('pid', True), ('filtered', False), ('operation', '')]:
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);event=self.fixture(root)
                section={'timestamp':'time', 'pid':'process_context',
                         'filtered':'order', 'operation':'action'}[field]
                event[section][field]=value
                (root/'normalized_events.jsonl').write_text(json.dumps(event)+'\n')
                with self.assertRaises(SampleError):SampleDirectory.open(root).validate(full=True)

    def test_missing_pid_on_both_sides_is_not_an_identity_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);event=self.fixture(root)
            event['process_context'].pop('pid')
            tree=json.loads((root/'process_tree.json').read_text())
            tree['node_index']['node_1']['process'].pop('pid')
            (root/'process_tree.json').write_text(json.dumps(tree))
            (root/'normalized_events.jsonl').write_text(json.dumps(event)+'\n')
            with self.assertRaises(SampleError):SampleDirectory.open(root).validate(full=True)

    def test_unknown_tree_root_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.fixture(root)
            tree=json.loads((root/'process_tree.json').read_text())
            tree['root_nodes']=['unknown']
            (root/'process_tree.json').write_text(json.dumps(tree))
            with self.assertRaises(SampleError):SampleDirectory.open(root).validate(full=True)

    def test_nested_tree_root_objects_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.fixture(root)
            tree=json.loads((root/'process_tree.json').read_text())
            tree['root_nodes']=[{'node_id':'node_1','process':{'pid':42},'children':[]}]
            (root/'process_tree.json').write_text(json.dumps(tree))
            self.assertEqual(SampleDirectory.open(root).validate(full=True)['status'],'passed')

if __name__=='__main__':unittest.main()
