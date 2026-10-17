# Copyright Ownership & Identity Record

This repository is published by **Trust Stackers** under the license in
[`LICENSE`](LICENSE). See [`NOTICE`](NOTICE) for the dual-license
declaration and third-party attribution.

This file records *why* Trust Stackers is entitled to license this work, and how
author identities map to people. It exists because a dual license (copyleft +
commercial) is only possible if the licensor owns — or holds sufficient rights
in — **all** of the copyright in the work.

## Copyright is not the same thing as a Git email

Ownership is determined by authorship and by the employment / contractor
agreements that assign it, not by the `user.email` configured in a repository.
An author who commits under two addresses is one author. This file keeps that
chain explicit and auditable.

## Identity map

| Git identity | Person | Canonical identity |
|---|---|---|
| `ShannonB <shannon@iotinventor.com>` | Shannon | `Shannon <simmunity@gmail.com>` |
| `ebjune <erika@simmunity.com>` | Erika Bjune | `Erika Bjune <erika@simmunity.com>` |

`shannon@iotinventor.com` and `simmunity@gmail.com` are the **same person**, who
had two GitHub identities configured on different machines. The mapping lives in
[`.mailmap`](.mailmap), so `git log`, `git shortlog`, `git blame` and
`git check-mailmap` all report a single identity.

History is deliberately **not** rewritten. A `git filter-repo --mailmap` pass
would change every commit hash for a cosmetic gain, break existing clones and
invalidate release tags; `.mailmap` achieves the same attribution
non-destructively.

## Ownership basis

- Copyright in this repository is held by **Trust Stackers**.
- New contributions are made under the [Contributor License Agreement](CLA.md),
  which grants Trust Stackers a perpetual, irrevocable copyright license to
  relicense contributions "under any license". That is what keeps the dual
  license possible.
- Contributions made **before** the CLA was introduced are covered by the
  contributors' employment or contractor IP assignment with Trust Stackers.

> **Records to keep on file (not a code change):** a signed PIIA, copyright
> assignment, or equivalent for each person in the identity map above. Without
> those records the `Copyright (C) 2026 Trust Stackers` assertion in the SPDX
> headers is not fully supported.

## Provenance of this repository

Carved out of the `lp2ptoip` monorepo on 2026-10-15. The last monorepo commit
that touched this repository's source paths (`packages`) was:

```
88dcb0bc54a79dd97a2649925b34d7c277692528  2026-10-14 20:26:56 -0700
added logging management mechanism to stack components
```

Verify with:

```bash
git -C <lp2ptoip> log -1 --format='%H %ad %s' --date=iso -- packages
```

## Verifying attribution

```bash
git log --format='%an <%ae>' | sort -u        # every identity in history
git check-mailmap '<shannon@iotinventor.com>' # -> Shannon <simmunity@gmail.com>
git shortlog -sne                             # counts, resolved through .mailmap
```
