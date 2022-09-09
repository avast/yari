## How to compile YARA for YARI

You need to the following repository (it is a submodule):

```
https://github.com/MatejKastak/yara/tree/yari
```

Compilation command:

```bash
./bootstrap.sh && CFLAGS="-fPIC" ./configure --enable-debug --disable-shared --enable-static --enable-cuckoo --enable-magic --enable-dotnet --with-crypto && make clean && make
```
