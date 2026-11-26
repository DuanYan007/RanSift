"""Read a standalone three-file sample without consulting corpus metadata."""
from dataclasses import dataclass
from pathlib import Path
import csv
import json
import math

FILES = ('raw_events.csv', 'normalized_events.jsonl', 'process_tree.json')
CSV_FIELDS = ['Time of Day', 'Process Name', 'PID', 'Operation', 'Path', 'Result', 'Detail']

class SampleError(ValueError):
    """Input-contract failure, with no host path in the diagnostic."""

@dataclass(frozen=True)
class SampleDirectory:
    root: Path

    @classmethod
    def open(cls, directory):
        root = Path(directory).absolute()
        if not root.is_dir() or root.resolve() != root:
            raise SampleError('Sample directory must be a real, non-symlink directory.')
        for name in FILES:
            p = root / name
            if p.is_symlink() or not p.is_file():
                raise SampleError(f'Required regular file missing or symlinked: {name}')
        return cls(root)

    def validate(self, *, full=False):
        """Check schemas and event/node identity; full streams all normalized rows.

        Raw CSV body membership is not checked by this structural validator.
        No model calls, binary execution, output files or fallback lookups occur.
        """
        try:
            with (self.root / FILES[0]).open(encoding='utf-8-sig', newline='') as f:
                if next(csv.reader(f), None) != CSV_FIELDS:
                    raise SampleError('Unexpected raw_events.csv columns.')
            tree = json.loads((self.root / FILES[2]).read_text(encoding='utf-8-sig'))
            if not isinstance(tree, dict) or not isinstance(tree.get('node_index'), dict) or not isinstance(tree.get('root_nodes'), list):
                raise SampleError('Invalid process_tree.json structure.')
            nodes = tree['node_index']
            roots = tree['root_nodes']
            root_ids = [root.get('node_id') if isinstance(root, dict) else root for root in roots]
            if not roots or any(not isinstance(key, str) or key not in nodes for key in root_ids):
                raise SampleError('Process tree roots must identify supplied nodes.')
            for key, node in nodes.items():
                if not isinstance(key, str) or not key or not isinstance(node, dict):
                    raise SampleError('Invalid process tree node.')
                process = node.get('process')
                if not isinstance(process, dict) or type(process.get('pid')) is not int or process['pid'] < 0:
                    raise SampleError('Each process tree node requires a nonnegative integer PID.')
            checked = 0
            with (self.root / FILES[1]).open(encoding='utf-8-sig') as f:
                for line in f:
                    if not line.strip():
                        continue
                    event = json.loads(line)
                    if not isinstance(event, dict) or any(not isinstance(event.get(k), dict) for k in ('order','time','action','target','detail','process_context')):
                        raise SampleError('Invalid normalized event structure.')
                    if type(event['order'].get('filtered')) is not int or event['order']['filtered'] != checked:
                        raise SampleError('Normalized event offsets are not contiguous from zero.')
                    timestamp = event['time'].get('timestamp')
                    if type(timestamp) not in (int, float) or not math.isfinite(timestamp):
                        raise SampleError('Normalized events require finite numeric timestamps.')
                    if not isinstance(event['action'].get('operation'), str) or not event['action']['operation'].strip():
                        raise SampleError('Normalized events require an operation name.')
                    process = event['process_context']
                    if type(process.get('pid')) is not int or process['pid'] < 0 or not isinstance(process.get('node_id'), str):
                        raise SampleError('Normalized events require an integer PID and node identifier.')
                    node = nodes.get(process.get('node_id'))
                    if not isinstance(node, dict) or node.get('process', {}).get('pid') != process.get('pid'):
                        raise SampleError('Normalized event process does not match the supplied tree.')
                    checked += 1
                    if not full:
                        break
            if not checked:
                raise SampleError('Normalized event stream is empty.')
        except SampleError:
            raise
        except (OSError, ValueError, TypeError, AttributeError, KeyError, OverflowError, csv.Error):
            raise SampleError('Unable to parse the supplied sample files.') from None
        return {'status': 'passed', 'validation': 'all_normalized_events' if full else 'header_tree_and_first_event',
                'normalized_events_checked': checked, 'raw_body_reference_check': 'not_performed',
                'files': list(FILES), 'model_requests': 0}
