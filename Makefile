target/release/yari: libyari
	cd yari-cli && cargo build -r

libyari: yara
	cd yari-sys && cargo build -r

yara: yari-sys/yara/bootstrap.sh
	cd yari-sys/yara && ./bootstrap.sh && CFLAGS="-fPIC ${CFLAGS}" ./configure --enable-debug --disable-shared --enable-static --enable-cuckoo --enable-magic --enable-dotnet --with-crypto && make clean && make

yari-sys/yara/bootstrap.sh:
	git submodule update --init --force

clean:
	cargo clean
	@cd yari-sys/yara 2> /dev/null && make clean

