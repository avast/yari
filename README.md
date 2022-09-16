# YARI - YARA Interactive

Interactive debugger for the [YARA](https://yara.readthedocs.io/en/stable/)
language written in Rust. Debugger directly calls `libyara` avoiding emulation
to get the most accurate results.

:rocket: Features:
- Call functions from modules
- Get the value of module constants
- Evaluate complex expressions
- Check the matches of strings
- Support for external variables

## Interactive shell

Binary accepts the same arguments as original `yara` binary.

```bash
λ yari /bin/sh
>> elf.number_of_sections
Ok(
    Value(
        "elf.number_of_sections",
    ),
)
Parsed expression Value("elf.number_of_sections")
Integer(26)
>>
```

## License

Copyright (c) 2022 Avast Software, licensed under the MIT license. See the
[`LICENSE`](https://github.com/avast/yari/blob/master/LICENSE) file for more
details.

YARI and its related projects uses third-party libraries or other resources
listed, along with their licenses, in the
[`yari-sys/LICENSE-THIRD-PARTY`](https://github.com/avast/yari/blob/master/yari-sys/LICENSE-THIRD-PARTY)
file.

This product includes software developed by the OpenSSL Project for use in the
OpenSSL Toolkit. (http://www.openssl.org/)
