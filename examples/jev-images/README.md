# Native Jev images and Box

This development example sends one nonsensitive generated image through AudiToad
to the fixed `jev-1.14.0` model. It exercises images separately in state,
instructions and choice criteria, an absent-object control, and a Box helper.
The image is a red mug and blue book on a white background. Its complete PNG bytes
are pinned in `bundle.json`; no OCR, crop or resize replaces the native image.
The native TypeSafe binding accepts whole-image parts and explicitly refuses a
partial region; it does not imply that the provider sees only a selected region.

`labels.json` records the visual labels and broad mug-edge intervals reviewed
before model calls. Five local numeric checks consume the committed Box fields.
They distinguish matching edge intervals from reported confidence. A well-formed
Box is an observation, not an audit verdict. The draft baseline retains
experimental outcomes; this example does not qualify general model accuracy.
JPEG header/transport behavior has separate product tests; this scene tests PNG.

From this directory, with `TYPESAFE_API_KEY` set and the current AudiToad binary
on your path, prepare the exact requests without issuing calls:

```text
auditoad scan --baseline baseline.json --input bundle.json --evaluators evaluators.json --profile development --report prepared.json --max-input-bytes 16777216 --max-request-bytes 8388608 --max-evidence-bytes 134217728 --max-provider-calls 5 --max-checks 10 --max-targets 1
```

Review the prepared requests, then add `--live` and select a fresh report path to
issue the five serial calls. The evaluator file explicitly enables the TypeSafe
image preview header. It leaves other evaluator configurations unchanged.
Generated reports are local output and should not be committed or distributed.

## Recorded development run

One run on 2026-10-14 issued five calls to `jev-1.14.0`, with no transport or
response-decoding errors. The labels, intervals and thresholds were fixed first.

| Check | Observed answer | Fixed-policy observation |
|---|---|---|
| Image in state | `red_mug`, probability 1.0, confidence 1.0 | Pass suggestion |
| Image in instructions | `red_mug`, probability 1.0, confidence 1.0 | Pass suggestion |
| Image in criteria | `matching_scene`, probability 0.72, confidence 0.58 | Review: below the 0.9 thresholds |
| Absent green apple | Noul 0.02 | Pass suggestion |
| Entire mug Box | left 0.09, top 0.33, right 0.45, bottom 0.67; confidence 0.84 | All five local ranges match |

The draft scan keeps all ten terminal outcomes `not_evaluated`, including the
local checks that consult the experimental Box. Correct selection with low
confidence stays unresolved. No threshold was lowered and no unchanged question
was repeated. This tests the PNG transport and this scene; JPEG has header and
transport unit coverage, with no live JPEG observation claimed.
The retained development scan ID is `5165c262-c681-47fc-8d71-2a6754ae4283`, with
report SHA-256 `a13af4dfd59a316173a0e759d579673b68cd5fa1437c6c436db59fb1b7adcd86`.

See [TypeSafe Images](https://docs.typesafe.ai/images) and
[Box](https://docs.typesafe.ai/primitives/box) for the provider protocol and preview
limits. AudiToad retains original file identity, request bytes and returned model
identity; it rejects changed bytes, unsupported media, bad references and invalid
Box coordinates. It does not silently prepare an out-of-bounds image for the service.
