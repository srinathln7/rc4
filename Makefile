# Build documentation
.PHONY: docs
docs:
	@cd ~/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/share/doc/rust && python3 -m http.server &
	@sleep 1 # Give the server a second to start
	@xdg-open http://localhost:8000/html/std/index.html

