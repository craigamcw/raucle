# Anonymisation checklist — IEEE S&P 2027 double-blind submission

This file is the authoritative pre-submission checklist for the
double-blind version of `main.tex`. It also describes the
camera-ready de-anonymisation, which is a mechanical operation.

## Current state (2026-05-27)

| Surface | Status | Note |
|---|---|---|
| `paper/main.tex` author block | Anonymised | `[Anonymised for double-blind submission]` |
| `paper/main.tex` body | Clean | No identity strings; uses third-person "we" / "our" consistent with double-blind conventions |
| `paper/references.bib` | Clean | No author URLs, no self-citations; external refs only |
| `paper/figures/*.mmd` | Clean | No identity strings |
| Acknowledgements section | Absent | Removed for double-blind; re-add at camera-ready if needed |
| Funding statement | Absent | None to declare |
| `paper/DRAFT.md` (working) | Internal — not submitted | OK to retain identity |
| `paper/eval/**` (reproducibility) | Internal — not in PDF | Will be uploaded separately to anon supplementary portal at submission time |
| Git tag `pre-anon` | Exists | Captures the de-anonymised state for trivial revert |

## Pre-submission verification

Before uploading the PDF, run:

```bash
paper/scripts/check-anon.sh
```

The script greps `main.tex` and `references.bib` for the canonical
identity strings (`raucle`, `craig`, `mcwilliams`, `craigamcw`,
`github.com/craig`, `raucle.com`) and exits non-zero if any match.

## Surfaces explicitly *out of scope* for double-blind

S&P treats the following as out-of-scope for double-blind under standard
practice; these may remain public/identified without affecting review:

- The `epic28-ltd/raucle` GitHub repository (public). Paper cites
  the implementation as `[anonymised for blind review]` and does not
  link the repository in the PDF.
- The raucle.com website. Paper does not reference it.
- Conference talks, blog posts, or social posts about the work,
  provided the PDF itself does not name them. Reviewers searching for
  technical terms may find the work; that is acceptable. The
  double-blind guard is on PDF cues, not on world-wide search.

## Camera-ready de-anonymisation (post-acceptance)

A single command restores the de-anonymised author block from the
`pre-anon` tag:

```bash
git checkout pre-anon -- paper/main.tex
# review the diff; commit
```

Then update:

- `\author{...}` with the actual author list.
- Acknowledgements section if any funding / collaborators need crediting.
- Citation of the open-source implementation by its real name in §1.5
  and §8 (replace `[anonymised for blind review]` and `[anonymised]`).

The mechanical operation should take under five minutes.

## Audit log

| Date | Action |
|---|---|
| 2026-05-15 | TeX shell created with anonymised author block from the start. |
| 2026-05-15 | `pre-anon` git tag pinned. |
| 2026-05-27 | This checklist created; pre-submission check script added. |
