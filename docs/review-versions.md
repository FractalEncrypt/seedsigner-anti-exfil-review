# Review snapshots, branches, and project identity

The project display name is **Airgap Anti-Exfil**. The existing repository URL
and historical names remain valid evidence identifiers. A future repository
slug rename, if any, is a separate link-migration operation.

## Which ref should a reviewer use?

- Use the default `main` branch to read the latest independently reviewed
  public reviewer hub.
- Use an immutable `review-hub-*` tag when citing or reproducing a historical
  snapshot.
- Use exact commits and trees from `repositories.json` when reviewing an
  implementation. Friendly branch names are not identity proofs.
- Candidate/development branches preserve work history but are not the default
  onboarding path unless a review request explicitly names one.

## Historical snapshots

| Snapshot | Git identity | Meaning |
| --- | --- | --- |
| `review-hub-v1-2026-08-21` | immutable historical tag | Initial public review hub |
| `review-hub-v1.1-2026-08-21` | immutable historical tag | Private-reporting clarification |
| `review-hub-v1.2-2026-08-22` | immutable historical tag | Gate 5 handoff state |
| `review-hub-v1.3-2026-08-22` | immutable historical tag | Frozen finalized-input handoff |
| Public v2 reviewer hub | `88c92b062e6abb7aba5190235d4b2ec8de9c1a6f` | Integrated v2 outside-review invitation; a matching immutable tag should be created only by a separately authorized publication operation |
| M9 bounded closure | `daeef82ceaaa9c597cd156c340d312c1254582b6` | Independently accepted technical closure and local publication candidate; preserved as the parent of the novice-testing documentation layer |

When a later usability candidate is accepted and published, record its exact
commit/tree and immutable tag here. Do not rewrite older tags or delete old
review branches merely to simplify the default landing page.

## GitHub timestamps are not tags

GitHub's “days ago” label beside a file or directory reports the most recent
commit that changed that path. It does not create a release boundary. The
commit hash and immutable tag are the durable boundary.

## Naming migration policy

Documentation may use **Airgap Anti-Exfil** before the repository slug changes.
Keep “formerly SeedSigner Anti-Exfil Review Hub” during the transition so old
citations remain understandable. Before any slug rename:

1. inventory cross-repository URLs, badges, scripts, archives, and review
   citations;
2. update and test clone/build commands in one reviewed documentation delta;
3. preserve old commit and tag identities;
4. verify GitHub redirects and every first-party link after the rename; and
5. record a hash-bound migration/read-back checkpoint.
