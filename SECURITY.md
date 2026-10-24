# Security for a public synthetic-only proof

All repository files, commits, workflow logs, draft PRs and created branches are public. Do not publish passwords, API tokens, private organization names, private project source, personal email addresses or system topology. GitHub Actions may print diagnostic outputs; never print its ephemeral token or upload private artifacts. Never connect private repositories or deploy a real system from this demonstration.

The workflow must fail closed on absent branch protection or source-SHA authorization. A passing synthetic proof does not grant authority in any other repository.
