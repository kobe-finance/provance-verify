# Security policy

provance-verify decides whether evidence is genuine, so a flaw that lets a
changed or forged bundle verify is a security issue. Examples: a check that
can be skipped, a signature or Merkle proof accepted when it should not be,
a key or certificate taken from the bundle instead of from the person
verifying, or any network access.

## Reporting a vulnerability

Email **security@provancelabs.org**. Do not open a public issue.

Please include the version (`provance-verify --version`), what you did, what
you expected, and, if you can, a bundle or a script that shows the problem.
Use synthetic data only: never send a real customer's evidence.

We acknowledge reports within three working days and keep you informed until
a fix is released. We credit reporters who want to be credited.

## Supported versions

The latest release receives security fixes.
