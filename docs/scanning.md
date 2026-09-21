# Scanning Guide

> How Vooda scans, what each scan option covers, and what it deliberately
> leaves out. For an introduction, start with the [README](../README.md).

Every scan — code or not — runs the same pipeline: pull the content,
flag credential candidates with detection rules, verify whether each
candidate still works, then let an AI model triage out the false
positives. What changes between scan types is **which content gets
pulled**.

---

## Scanning a repository

Open a repository and use **Run Scan**. The three options answer three
different questions.

| Option | Question it answers | Typical run time |
|---|---|---|
| **Scan Current Code** | "What's in my code right now, since the last scan?" | Seconds |
| **Force Full Re-Scan** | "Re-check every file from scratch, trust nothing cached." | Minutes |
| **Scan Git History** | "What was ever committed — including secrets since deleted?" | Minutes to tens of minutes |

### Scan Current Code

The default, and the one to use day to day. Vooda remembers the last
commit it scanned on each branch and re-scans only the files that
changed since then.

A few things to know:

- **It falls back to a full scan automatically** when there's no
  usable checkpoint — the first scan of a repository, an uploaded
  archive with no git data, or a branch whose history was rewritten by
  a force push. You don't need to do anything; the scan just takes
  longer that once.
- **It notices deleted files.** When a file is deleted between two
  scans, the findings pointing at it are tagged "Not in current code".
  They stay open — the credential still needs rotating — but you can
  see which exposures are no longer in your working tree.

### Force Full Re-Scan

Ignores the checkpoint and the result cache and re-runs the complete
rule set over every file in the working tree. Same commit as a normal
scan, same files — the difference is that nothing is reused from a
previous run.

Use it when:

- You've changed which paths or file types are in scope.
- You have reason to doubt the previous result and want a clean
  baseline.

You do **not** need it after a detection-rule change. Vooda records
which rule set each branch was last scanned with, and when that set
moves — a rule added or edited, or an updated Vooda release — the next
scan walks every file once on its own, then returns to incremental
scanning.

A full re-scan also flags findings whose file is no longer in the
repository as "Not in current code" — it does not close them, for the
reason described below. It does this only on your default branch, so a
full scan of a feature branch never mislabels a file that simply lives
on main.

You do **not** need it for routine scanning. It costs real time on a
large repository and, on unchanged code, reaches the same conclusion.

### Scan Git History

Walks the commit history and scans what each commit *added*, plus each
**commit message**. This is the only option that finds a secret that
was committed and later removed — the credential that no longer
appears in any file but is still sitting in the repository's history,
and therefore in every clone anyone has ever made — and the only one
that reads the messages themselves, where `git commit -m "temp, using
key ..."` leaves a credential that never entered a file at all.

History findings carry the commit, the author and the date the secret
was introduced, so you know who to ask and how long it has been
exposed. A secret that's still present in your current code is shown
at its present-day location; one that has been scrubbed from current
code is labelled as **history-only**, because deleting the file did
not make the credential safe.

Two practical notes:

- **It complements a code scan — it doesn't replace one.** The walk
  covers the **5,000 most recent commits**, and the scan record says so
  when a repository has more history than that, rather than letting a
  partial result look like a clean one. On a repository older than the
  window, a secret added before it and never touched since is found by
  *Scan Current Code* or *Force Full Re-Scan* (it's still in your
  files), not by the history walk.
- **A secret in a commit message can only be fixed by rotating it.**
  There is no file to edit and no way to remove it from clones that
  already exist, so Vooda marks these findings as history-only and
  never closes them because a file went away.
- **It doesn't move your checkpoint.** Running a history scan has no
  effect on where your next incremental scan starts.

Run it once when you onboard a repository, and again after any
incident where a credential may have been "fixed" by deleting it.

### Which branch gets scanned

Your **default branch**, unless you name another one. The Run Scan menu
has a **Branch** field that applies to whichever option you pick, and
the API accepts the same value as `branch` in the scan config.

Two things to know:

- **A branch that doesn't exist upstream falls back to the default**,
  and the scan record names the branch actually read — it never reports
  a branch it didn't scan.
- **Only a default-branch scan closes findings for deleted files.** A
  file missing from a feature branch is not evidence that it is gone
  from your codebase, so a branch scan adds findings but never closes
  them.

---

## Scans that run without you

| Trigger | What it scans |
|---|---|
| **Push webhook** | The files changed by the push |
| **Pull request webhook** | The code changed by the pull request |
| **CLI / CI gate** | The files or diff you point it at |
| **Pre-commit hook** | Staged changes, before the commit is created |
| **Scheduled scans** | Repositories and sources on a recurring schedule *(Enterprise)* |

Push and pull-request scanning is enabled per repository. Results can
be posted straight back onto the pull request so a developer sees the
finding without leaving the review.

---

## Secrets outside your code

Credentials leak into conversations at least as often as into files —
pasted into a ticket to unblock a colleague, dropped into a pull
request description, attached to a bug report. **None of that lives in
your repository**, so no code scan will ever see it, however deep it
goes.

That content is covered by **Sources**, configured separately from
repositories:

| Source | Discussion content scanned | Edition |
|---|---|---|
| **Jira** | Issue descriptions, comments, custom text fields, attachments | Community |
| **ServiceNow** | Incident, change and service request descriptions and comments | Community |
| **Azure DevOps** | Work item descriptions and discussion | Community |
| **GitHub Issues** | Issue descriptions and comments, plus pull request descriptions and comments | Enterprise |
| **Bitbucket** | Issue and pull request descriptions and comments | Enterprise |

Connecting a repository for code scanning does **not** connect its
issues and pull request discussion — that's a separate source, with
its own credentials and its own scope. If pull request discussion
matters to you, add it deliberately.

---

## How a finding gets closed

A finding leaves your open list in one of three ways:

1. **The credential stops working.** Vooda re-checks live credentials
   on each scan; a key that was live and is now revoked is reflected
   automatically. This is how Vooda sees that a secret was rotated —
   it detects the outcome, it does not perform the rotation.
2. **You classify it** — false positive, test credential, or accepted
   risk with a reason.
3. **The repository or source is removed** from Vooda.

### Deleting the file does not close it

When a file disappears from your code, the finding is tagged **"Not in
current code"** and stays open. It is not resolved, because deleting a
file does not revoke a credential: the value is still in every commit
that carried it, and in every clone and fork already made.

This is the position every established secrets scanner takes — GitHub
never auto-closes an alert when the token is removed, GitGuardian
resolves on revocation via its validity checker, and GitLab removed
auto-resolution from its secret detection for exactly this reason.
Rotate the credential and Vooda will see it go inactive.

Non-git sources behave differently: a deleted Jira comment really is
gone, with no history behind it, so those findings do close on
deletion.

Closures of the first two kinds feed the dashboard's mean time-to-fix.
Removing a repository does not — deleting the thing you were measuring
isn't a fix.

---

## What Vooda does not scan today

Stated plainly, so you can cover these elsewhere rather than assume
they're handled:

- **Inline code-review comments** on a pull request — the threaded
  remarks attached to specific lines of a diff. Pull request
  *descriptions* and *general* comments are covered by the GitHub
  Issues and Bitbucket sources; line-level review threads are not yet.
- **GitLab issue and merge request discussion.** GitLab *code* is
  scanned like any other repository; its discussion surface has no
  connector yet.
- **GitHub Discussions.**
- **Commits older than the 5,000 most recent** in a history scan. The
  scan record tells you when this applies to your repository.

These are known gaps, not oversights in your configuration. They're
tracked in the open — see the repository's issues and discussions.
