# AI usage: dsc26-cyb-w03

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools
<!-- Which AI tools you used (or "none"), and for which parts of the task. -->
- Claude (claude.ai chat): Helped explain the task and security concepts, and provided initial drafts of the files.

## What AI got wrong
<!-- At least one thing an AI tool got wrong that you changed, and how you noticed:
     a test, the docs, running it. -->

- I did not find a mistake in the AI's code. What I checked: I ran all 157 tests (policy, validation, passwords and the 5 public tests) and they all pass, and the grader's hidden tests passed too.

## In my own words
<!-- One or two sentences each, written without AI. -->

1. Returning 404 instead of 403 prevents clients from discovering whether another client's document exists by trying different document IDs.

2. A hash shorter than 32 bytes is easier to guess by chance. For example, a one-byte hash has only 256 possible values, giving a random guess a 1 in 256 chance of matching.
