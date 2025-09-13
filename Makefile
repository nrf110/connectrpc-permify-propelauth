.PHONY: clean
clean:
	rm -rf dist

.PHONY: update
update:
	go mod tidy

.PHONY: test
test: clean update
	go test -v ./pkg/