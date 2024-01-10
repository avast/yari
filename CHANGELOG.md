# Changelog
All notable changes to this project will be documented in this file.

# 0.2.1 (2024-01-10)

* chore: Extend .dockerignore
* cc57e25 chore: Cache cargo index in manylinux2014 docker image
* cc55548 chore: Update the lock file

# 0.2.0 (2024-01-10)

NOTE: Many thanks to (@3c7)[https://github.com/3c7]

* Combining aarch64 with linux target_os
* Implemented conditional compilation for aarch64
* Implemented macOS (intel) build in Github Actions
* Implementing Makefile for easier manual build process
* Update Readme.md: Add installation & info
* chore(deps): Update deps
* chore: Add way to link additional libs
* chore: Stop using deprecated `Python::acquire_gil()`
* ci: Create dependabot.yml
* ci: Github Action for building windows wheels
* ci: Testing Github Actions for Windows
* feat: Add new argument to `yr_re_compile`
* fix: Return error when yara module is not found

# 0.1.6 (2023-02-20)

- feat: Start using vanilla YARA API (#19)
- ci: Add tests for bundled bindings

# 0.1.5 (2023-02-04)

- ci: Update openssl to 3.0.7

# 0.1.4 (2023-02-03)

- build: Link YARA statically for Linux
- ci: Github Action for Win Python wheels (enables support for python3.11) (#17)
- ci: Fix the zlib version in Dockerfile

# 0.1.3 (2022-09-26)

- fix release process

# 0.1.2 (2022-09-26)

- feat: Add support for `filesize` and `entry_point` in complex expressions
- fix: Heap corruption on Windows platform

# 0.1.1 (2022-09-20)

- fix: Parse complex expressions starting with a string (#9)

# 0.1.0

- Initial release
