# Contributing

Contributions welcome. Please:

1. Fork the repo
2. Create a feature branch
3. Run tests: `make test`
4. Submit a PR

## Development

```bash
go mod tidy
make build
make test
```

## Running benchmarks

```bash
go build -o benchmark ./cmd/benchmark
./benchmark
```
