# Pull Request Template

## Important Notice
**IMPORTANT: Please do not create a Pull Request without creating an issue first.**

*Any change needs to be discussed before proceeding. Failure to do so may result in the rejection of the pull request.*

## Title Suggestion
Please start your pull request title with `[Type]` followed by a brief description of the changes. For example:
- `[Fix] Resolve memory leak in logger`
- `[Feature] Add support for custom log formats`

If you are merging branches, please use the following default title format:
- `[Merge] Merge dev (your source) into main (target branch)`

## Description
Please include a summary of the change and which issue is fixed. Please also include relevant motivation and context.

Explain the **details** for making this change. What existing problem does the pull request solve?

<!-- Example: When "Adding a function to do X", explain why it is necessary to have a way to do X. -->

## Type of change
Please delete options that are not relevant.

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] This change requires a documentation update

## How Has This Been Tested?
Demonstrate the code is solid. Example: The exact commands you ran and their output, screenshots / videos if the pull request changes UI.

<!-- Make sure tests pass on both Travis and Circle CI. -->

- [ ] Test A
- [ ] Test B

## Test plan (required)
Provide a detailed test plan to ensure the code is reliable. Include the exact commands you ran and their output, screenshots / videos if the pull request changes UI.

## Code formatting
Run `gofmt -s -w .` to format your code.

<!-- See the simple style guide. -->

## Checklist:
- [ ] My code follows the style guidelines of this project
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings

## Closing issues
Put `closes #XXXX` in your comment to auto-close the issue that your PR fixes (if such).

