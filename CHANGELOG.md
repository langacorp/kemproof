# Changelog

All notable changes to this project are recorded here.
Dates are the date of the commit, not of a release.

## 2026-09-04

- README: the package is on Packagist, and says so — badge and the one-line
  install. Before this, someone arriving from the repository had no way to know
  `composer require langacorp/kemproof` existed.
- README: says what Composer installs and what it does not — `liboqs` is a
  system library and has to be there already.
- composer.json required PHP 8.1 while the README promised 8.0, nine lines
  from the install command. Measured, not chosen: the code parses on 8.0 and a
  real ML-KEM-768 exchange completes on it. The floor is 8.0, and the self-test
  now runs on 8.0, 8.2 and 8.4 so the declared floor is an exercised one.
- README: DOI badge. The concept DOI, which follows every future release.
- README: PHP 8.0 is a floor, not a recommendation. It no longer receives
  security fixes upstream. The code runs on it; that is a different sentence
  from run it, and a reader takes the second one if you do not write the first.
- CITATION.cff said version 1.0.0 two releases after 1.0.0, and Zenodo reads
  that file: the archived record takes its abstract from it word for word.
  Version and date now match the release, and the concept DOI is in it.

## 2026-08-30

- kemproof: attest an ML-KEM-768 key exchange, and say only what that proves
