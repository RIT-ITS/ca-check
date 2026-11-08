IMAGE ?= localhost/ca-chain-check:latest
ROOTS_URL ?= https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites
STORES_URL ?= https://ccadb.my.salesforce-sites.com/ccadb/AllIncludedRootCertsCSV
MICROSOFT_URL ?= https://ccadb.my.salesforce-sites.com/microsoft/IncludedCACertificateReportForMSFTCSVPEM
MERMAID_VERSION ?= 11.4.1
SWAGGER_UI_VERSION ?= 5.17.14
HELM ?= podman run --rm -v $(CURDIR)/deploy/helm:/charts:Z docker.io/alpine/helm:3.16.4

.PHONY: build test run image up down refresh-roots refresh-mermaid refresh-swagger helm-lint helm-template

build:
	CGO_ENABLED=0 go build -trimpath -o bin/server ./cmd/server

test:
	go vet ./... && go test ./...

run: build
	set -a; [ -f .env ] && . ./.env; set +a; LISTEN_ADDR=127.0.0.1:8080 ./bin/server

image:
	podman build -t $(IMAGE) -f Containerfile .

up:
	podman compose up -d --build --force-recreate

down:
	podman compose down

refresh-roots:
	curl -fsSL -o assets/mozilla-roots.pem '$(ROOTS_URL)'
	curl -fsSL -o assets/root-stores.csv '$(STORES_URL)'
	curl -fsSL -o assets/microsoft-roots.csv '$(MICROSOFT_URL)'
	@grep -c 'BEGIN CERTIFICATE' assets/mozilla-roots.pem

refresh-mermaid:
	curl -fsSL -o web/vendor/mermaid.min.js https://cdn.jsdelivr.net/npm/mermaid@$(MERMAID_VERSION)/dist/mermaid.min.js

refresh-swagger:
	mkdir -p web/vendor/swagger-ui
	for f in swagger-ui-bundle.js swagger-ui.css LICENSE; do \
	  curl -fsSL -o web/vendor/swagger-ui/$$f https://cdn.jsdelivr.net/npm/swagger-ui-dist@$(SWAGGER_UI_VERSION)/$$f || exit 1; \
	done

helm-lint:
	$(HELM) lint /charts/ca-chain-check

helm-template:
	$(HELM) template ca-chain-check /charts/ca-chain-check
