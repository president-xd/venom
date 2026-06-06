# How "success" is decided - the oracle

This is the heart of "enterprise-grade." Real business-logic wins are **state
transitions**, not success banners. The oracle lives in
[`venom/cognition/objective.py`](../venom/cognition/objective.py) and decides a win in
strict priority:

1. **Differential (preferred, app-agnostic).** A concrete `win_action`
   (`{"method","path","data"}`) that is **denied** for the un-escalated user
   (baseline) and **succeeds** after the exploit. No product-specific string required.

   - When the privilege is carried *in* the winning request (e.g. a stolen token in a
     BOLA delete, a tampered price, a forged JWT header), the bare re-run is still
     denied - so the oracle also accepts the win if the **exploit's own request trace**
     shows the win-action path succeeding (`action_succeeded_in_trace`). This still
     requires a realistic success marker, so an incidental `200` is not counted.

2. **Operator-defined marker (only if explicitly set).** A `success_text` /
   `win_signals` substring that the **operator** supplies for a specific target.

3. **Neither defined -> an honest "unknown" (`False`).** VENOM never guesses success
   from a baked-in banner.

`_DEFAULT_SIGNALS` is **empty**. There are no product-baked default signals, asserted
by `tests/test_tools.py::test_objective_does_not_rely_on_baked_in_lab_strings`.

## Why this matters for real apps

A real enterprise app has no "is-solved"/"congratulations" banner. An oracle that
depends on one would confirm nothing on a real target (or, worse, false-positive on a
similar string). The differential oracle works the way a senior tester reasons:

> success = (this action was forbidden to me) AND (after my exploit it worked)

## What a realistic marker looks like

When the differential is "the action succeeds and the app returns a state signal", the
marker is something the app genuinely emits, not a test banner:

- **Access-control wins:** the baseline is a `403`; success is the real result text
  (e.g. a JSON `deleted`/`removed`, a "wire sent" confirmation).
- **Economic / logic wins:** the baseline is the *honest* request (buy at the listed
  price, deploy to **staging**, transfer 1 unit from your **own** account) which returns
  no marker; the exploited request returns a genuine confirmation the app produces (an
  order/receipt line, a "deployed to PRODUCTION", a compliance/audit alert, an unlocked
  premium feature, etc.).

The oracle is exercised by the shipped test suite:
`tests/test_tools.py::test_objective_does_not_rely_on_baked_in_lab_strings` asserts the
default objective never confirms from a baked-in banner. Whether a *specific* exploit is
synthesized for a given target is the reasoning model's job; the confirmation itself is
deterministic and string-free. See [capabilities-and-limits.md](capabilities-and-limits.md).

## Where `is-solved` is still legitimate

The deterministic PortSwigger solvers in `venom/flows/*` use the lab's `is-solved`
banner as ground truth - that is correct for them (they target those specific labs). On a
real, bannerless app they simply do not fire. The general engine (`cognition/`) carries
**no** `is-solved` string.
