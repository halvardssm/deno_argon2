install_wasm_pack:
	cargo install wasm-pack
build: install_wasm_pack
	wasm-pack build --target web
	rm -rf pkg/.gitignore