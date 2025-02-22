.PHONY: clean clippy

clean:
	cargo clean
	rm -rf .wrangler
	rm -rf node_modules

clippy:
	cargo clippy
