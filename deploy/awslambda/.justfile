function-package:
	@ mkdir -p dist
	@ CGO_ENABLED=0 GOOS=linux go build -o dist/bootstrap main.go  # Compile main.go → function/main
	@ cp .cerbos.yaml dist/.cerbos.yaml
