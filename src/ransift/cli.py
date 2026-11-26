"""Public standalone sample-directory commands."""
import argparse
import json
from .sample import SampleDirectory, SampleError
from .runtime import analyze, AnalysisError

def main(argv=None):
    parser=argparse.ArgumentParser(prog='ransift')
    subs=parser.add_subparsers(dest='command',required=True)
    validate=subs.add_parser('validate',help='Validate sample files without model calls')
    validate.add_argument('--sample-dir',required=True)
    validate.add_argument('--full',action='store_true',help='Check every normalized event against the supplied tree')
    run=subs.add_parser('analyze',help='Analyze a three-file sample directory')
    run.add_argument('--sample-dir',required=True)
    run.add_argument('--output',required=True,help='New directory for generated evidence and analysis results')
    run.add_argument('--config',help='Explicit user model configuration JSON')
    run.add_argument('--static-sample',help='Optional explicitly supplied local binary; never downloaded or executed')
    run.add_argument('--prepare-only',action='store_true',help='Build local evidence only, with no model calls')
    args=parser.parse_args(argv)
    try:
        if args.command=='validate':
            result=SampleDirectory.open(args.sample_dir).validate(full=args.full)
        else:
            result=analyze(args.sample_dir,args.output,config_path=args.config,
                static_sample=args.static_sample,prepare_only=args.prepare_only)
    except (SampleError,AnalysisError) as exc:
        parser.exit(2,f'Input/configuration error: {exc}\n')
    except (OSError,ValueError,RuntimeError) as exc:
        parser.exit(2,f'Analysis could not complete ({type(exc).__name__}); inspect the local output if created.\n')
    print(json.dumps(result,indent=2))
    return 1 if result['status']=='failed' else 0

if __name__=='__main__':
    raise SystemExit(main())
