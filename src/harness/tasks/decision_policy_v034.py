"""Evidence weighting shared by assessment, semantic review and adjudication.

This is reasoning guidance, not a verdict rule or a substitute for evidence.
It contains no sample identities, ground truth, thresholds or network calls.
"""

VERSION = 'dev-v034-evidence-weighting'

EVIDENCE_WEIGHT_POLICY = (
    ' Evidence-weighting policy v034: '
    'Compare the explanations for the substantive observed actions, not the number of routine and unusual events. '
    'Routine DLL loading, locale queries, registry reads and device enumeration can coexist with an attack; '
    'they explain those operations and do not contradict an independent malicious action. '
    'For each competing interpretation, distinguish an observed supporting fact from a merely possible story. '
    'Apply this distinction equally to benign and malicious explanations. An uninspected artifact is not '
    'positive evidence that it is an installer, diagnostic or legitimate instructional output. Conversely, '
    'an unexplained artifact or the absence of authorization is not itself evidence of malicious intent. '
    'Compare the contextual evidence and the unconfirmed premises needed by each explanation. '
    'For an attempted action, distinguish the requested objective from its success. A failure result limits '
    'claims about achieved effects at that target; it does not establish a benign objective, contradict a '
    'successful operation at a different target, or require every stage of an attack to succeed. '
    'For a possible ransom note, evaluate artifact creation and writing, target identity, process attribution, '
    'the order and scope of placement attempts, and corroborating behavior together. A name alone does not '
    'establish extortion content. Unavailable content limits what can be said about that content; missing '
    'execution, display, completed encryption or user-visible damage is not a universal requirement for '
    'recognizing an otherwise supported malicious deployment attempt. Do not invent note contents or a '
    'copy relationship between same-named files. If no observed evidence distinguishes an extortion artifact '
    'from legitimate output, state that evidentiary limit rather than fabricating semantic confirmation. '
    'NTFS metadata objects, including $MFT, $Bitmap and $LogFile, can receive filesystem-maintenance I/O '
    'during ordinary application activity. Process attribution, paging I/O, non-cached I/O, successful writes '
    'and operation counts alone do not prove that the program deliberately opened or overwrote raw metadata. '
    'Use available open/access records, request details, offsets, operation continuity and raw-device access '
    'to assess whether deliberate low-level manipulation is supported; record missing information explicitly. '
    'A metadata-write detector establishes the recorded write pattern, not destructive intent. Do not '
    'automatically treat metadata I/O as benign either: retain independently supported raw writes and '
    'destructive context when present. '
    'A reviewer objection is an evidentiary question, not a replacement observation or a binding verdict. '
    'Resolve whether each objection contradicts the observed conduct, limits only an asserted effect, or '
    'exposes a premise needed by a competing explanation. A change of label must explain the decisive '
    'evidence or corrected inference; absence of unavailable information alone does not support a new label. '
    'The initial label has no presumption of correctness and may be changed in either direction. '
    'Keep exactly one malicious or benign label under the existing binary criterion, with specific '
    'uncertainties in the rationale. This policy supplies no missing observations and no default class. '
)

AGENT_OVERRIDES = {
    'file_transformation': {
        'required_checks_append': [
            'Separate process-attributed filesystem-maintenance I/O from evidence of deliberate raw metadata access; inspect available request context before inferring destruction.',
        ],
        'exclusions_append': [
            'Successful writes, paging/non-cached flags, or repeated $MFT/$Bitmap/$LogFile activity alone do not establish intentional metadata corruption; preserve the observations without asserting an unobserved API request or damage.',
        ],
    },
    'ransom_note': {
        'required_checks_append': [
            'Relate successful artifact creation/writing and any later placement attempts by process, target and time; distinguish each target and each operation result.',
            'Distinguish observed artifact deployment, inferred purpose and unknown contents; state whether content bytes are actually supplied by an available evidence source.',
        ],
        'exclusions_append': [
            'Do not invent ransom-note contents from a filename or infer that an uninspected artifact is legitimate output; both interpretations require contextual support.',
            'Do not require artifact execution, display or successful encryption to report an observed artifact-writing or placement attempt; do not claim extortion content without content evidence.',
        ],
    },
}
