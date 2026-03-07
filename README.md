# CrabLoader

![](banner.png)

A Cobalt Strike User-Defined Reflective Loader written entirely in Rust. I just wanted to figure out how hard it would be to build this. Turns out it's not that hard. I might add a sleep obfuscation feature at some point. Right now, it is just a basic loader without any special features. The only "opsec safety" feature is that it does not use RWX pages at any point.

# Usage

Download the release and load the `.cna` file.

You could compile it yourself. Make sure you use the MSVC toolchain and the release profile. You can use the `extractor` that is included to extract the `.text` section of the loader. For example:

```
cd extractor
cargo run --release -- ../target/release/crabloader.exe ../bin/crabloader.bin
```

# Cobalt Strike C2 Profile

I used this profile for testing: https://github.com/BC-SECURITY/Malleable-C2-Profiles/blob/master/APT/apt1_virtuallythere.profile

It does not contain settings to change memory indicators, only network stuff. So I'm guessing all the defaults work. If you change the MZ header with `magic_mz_x64`, the loader will not work as it searches for that header.

# Credits

- For the loader part: https://github.com/fancycode/MemoryModule
- For the CNA: https://github.com/kyleavery/AceLdr
