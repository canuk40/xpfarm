# XPFarm

## Installation

```bash
go install github.com/a3-n/xpfarm@latest
```

## Build

```bash
go build -o xpfarm

./xpfarm 
./xpfarm -debug
```

## Docker

```bash
# Using Docker Compose
docker-compose up --build

# Using standard Docker
docker build -t xpfarm .
docker run -p 8888:8888 -v $(pwd)/data:/app/data -v $(pwd)/screenshots:/app/screenshots xpfarm
```

## TODO

- [ ] Vuln scan nuclei only
- [ ] Global Search redo
- [ ] Agent Hell
- [ ] SecretFinder JS
- [ ] Repo detect/scan
- [ ] Mobile scan
- [ ] Custom Module?
