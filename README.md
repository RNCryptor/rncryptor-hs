[![Build Status](https://travis-ci.org/RNCryptor/rncryptor-hs.svg?branch=master)](https://travis-ci.org/RNCryptor/rncryptor-hs)
[![Build status](https://ci.appveyor.com/api/projects/status/vj3d35qptms3q23w?svg=true)](https://ci.appveyor.com/project/adinapoli/rncryptor-hs)
[![Coverage Status](https://coveralls.io/repos/github/RNCryptor/rncryptor-hs/badge.svg?branch=master)](https://coveralls.io/github/RNCryptor/rncryptor-hs?branch=master)

# Haskell Implementation of the RNCryptor spec
This library implements the specification for the [RNCryptor](https://github.com/RNCryptor)
encrypted file format by Rob Napier.

# Current Supported Versions
* V3 - [Spec](https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md)

# TODO
- [ ] Key-based      test vectors
- [ ] Key-derivation test vectors
- [ ] Profiling & optimisations

# Contributors (Sorted by name)
- Alfredo Di Napoli (creator and maintainer)
- Rob Napier (gave me the key insight to use the previous cipher text as IV for the new block)
- Tim Docker (Added decryptEither and gave us momentum in turning decrypt into a total function)
- Tom Titchener (added support for HMAC validation)

# Contributions
This library scratches my own itches, but please fork away!
Pull requests are encouraged.
