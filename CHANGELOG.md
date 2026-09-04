# Changelog

All notable changes to this project are recorded here.
Each entry is a release. The heading carries the tag and the date the release
was published. Work that is tagged but never released says so.

## v1.1.3 — 2026-09-04

- README: PHP 8.0 is a floor, not a recommendation. It no longer receives
  security fixes upstream. The code runs on it; that is a different sentence
  from run it, and a reader takes the second one if you do not write the first.
- CITATION.cff said version 1.0.0 two releases after 1.0.0, and Zenodo reads
  that file: the archived record takes its abstract from it word for word.
  Version and date now match the release, and the concept DOI is in it.

## v1.1.2 — 2026-09-04

- composer.json required PHP 8.1 while the README promised 8.0, nine lines
  from the install command. Measured, not chosen: the code parses on 8.0 and a
  real ML-KEM-768 exchange completes on it. The floor is 8.0, and the self-test
  now runs on 8.0, 8.2 and 8.4 so the declared floor is an exercised one.
- README: DOI badge. The concept DOI, which follows every future release.

## v1.1.1 — 2026-09-04

- README: the package is on Packagist, and says so — badge and the one-line
  install. Before this, someone arriving from the repository had no way to know
  `composer require langacorp/kemproof` existed.
- README: says what Composer installs and what it does not — `liboqs` is a
  system library and has to be there already.

## v1.1.0 — 2026-09-03

Tagged, never released: there is no GitHub release for this tag, so this
version is not archived on Zenodo.

- README: point to the other five tools, and say what this one is not.
- composer.json: make the PHP library installable.

## v1.0.0 — 2026-08-30

- kemproof: attest an ML-KEM-768 key exchange, and say only what that proves
