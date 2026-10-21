# STUDY-SITE: learner-continuity comparison (2026-10-21)

**Review stage:** implementation; visual screenshots and browser task observation pending.

## Released products inspected

1. **Khan Academy** (direct learning-product comparison)
   - Official progress and mastery documentation: https://support.khanacademy.org/hc/en-us/articles/360032987591
   - Official self-paced mastery: https://support.khanacademy.org/hc/en-us/articles/360007253831-Using-self-paced-practice-and-Mastery-in-the-classroom
   - Pattern: users retain visible learning progress over sessions and distinguish practice from mastery.
   - Limitation: a full mastery system would be disproportionate for one lecture's sixteen problems.
2. **Brilliant** (direct interactive learning-product comparison)
   - Official learning experience: https://brilliant.org/faq/
   - Official progress reporting (updated October 6, 2026): https://brilliant.org/help/schools-and-educators/assignment-and-progress-reporting-guide/
   - Pattern: guided interactive lessons with progress and immediate feedback; incomplete and completed work remain distinguishable.
   - Limitation: score-based adaptive curriculum and subscriptions are not appropriate for a local, single-course handout.
3. **Lichtblick** is intentionally **not** a comparator here: robotics telemetry software is irrelevant to the learning journey.

## Confirmed gap in current code

Before this branch, `app.js` always initialized `selected=0,step=0`.
It persisted only manually marked lesson completion, not the user's **current problem or worked solution step**.
Reopening a 16-problem study session therefore sent the learner back to Example 2.1 regardless of where study stopped.

This is a concrete journey defect, not a matter of palette preference.

## Milestone delivered in this branch

- Stable lesson-ID + step checkpoint stored locally, independent from manually checked completion.
- Restore last lesson and exact explanation step after refresh/reopening.
- Clamp outdated steps if course material changes; safely reset invalid or removed IDs.
- Work when browser storage is disabled or malformed.
- Obvious **Continue last problem** action on the top section for returning/in-progress learners.
- Respect reduced-motion preference, preserve focus indication, avoid intercepting arrow keys while other controls hold focus.
- Node built-in regression tests and pull-request CI; no new runtime dependencies.

## Required review evidence before merge

- Open the actual UI with desktop and mobile browser widths; capture screenshots at the PR commit.
- Open Problem 2.4 step 3, refresh, verify same heading and same step.
- Refresh after manually marking a completion; verify completion count and saved position do not interfere.
- Verify next/previous problems, RTL keyboard behavior, quiz interaction, focus, and mobile sidebar.
- Simulate storage exceptions and corrupted saved JSON.
- Run `node --test tests/study-progress.test.cjs`, `node --check app.js`, and the CI workflow.
- Confirm fonts render and MathJax equations remain legible.
- Compare task completion time and clarity against the identified reference workflows.

## Remaining important shortcomings

- Clicking **Mark completed** does not demonstrate understanding; quiz correctness is not linked to mastery.
- There is no cumulative mixed-question practice exam or spaced review.
- A source-faithful verification of all handout diagrams and symbolic answers remains a separate academic quality gate.
- The page is a single-lecture product, not a Khan Academy / Brilliant equivalent.

**Verdict:** scoped learner-continuity improvement proposed for review. No claim of visual parity, mastery parity, or end-to-end browser acceptance.
