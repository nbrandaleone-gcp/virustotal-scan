# Makefile
# Using this as part command alias and traditional Makefile

default: help

# Variables
TARGET=websockets
PROJECT := $(shell gcloud config get-value project) 
PROJECT_ID := $(strip $(PROJECT))
DOCKER_REPO=my-docker-repo
IMAGE_NAME=kemal-redis-chat
IMAGE_TAG=0.1
IMAGE_TAG ?= latest
# Google Artifact Registry format
IMAGE_URI="us-central1-docker.pkg.dev/$(PROJECT_ID)/$(DOCKER_REPO)/$(IMAGE_NAME):$(IMAGE_TAG)"

# Rules

.PHONY: all
## Build and deploy the container 
# Similar to `gcloud run deploy --source=.`
all: build/cloud deploy

.PHONY: watch
## Locally run program with dynamic recompile
watch:
	./dev/watch.sh $(IMAGE_NAME)

.PHONY: run
## Run program
run:
	crystal run src/$(IMAGE_NAME).cr

.PHONY: deploy
## Deploy container to Cloud Run
deploy:
	@echo "======================"
	@echo "Deploying to Cloud Run"
	@echo "======================"
	gcloud run deploy $(TARGET) \
	--allow-unauthenticated \
	--source . \ # --image $(IMAGE_URI)
	--allow-unauthenticated \
	--region us-central1 \
	--max-instances 10 \
	--concurrency 100 \
	--timeout 3600 \
	--network=default \
	--subnet=default \
	--vpc-egress=private-ranges-only \
	--set-env-vars REDIS=${REDISHOST} \
	--set-env-vars DEBUG="false"

.PHONY: build/local
## Compiles source using shards command
build/local:
	@shards build $(IMAGE_NAME)

.PHONY: build/cloud
## Build docker container in Cloud
build/cloud:
	@echo "======================"
	@echo "Building container via Cloud Build"
	@echo "======================"
	gcloud builds submit --tag $(IMAGE_URI)

deps:
	@which docker

## Build docker container locally
build/docker: deps
	@docker build -f Dockerfile -t $(IMAGE_URI) .

## Configures Docker to authenticate to Google Artifact Registry
docker/login:
	gcloud auth configure-docker us-central1-docker.pkg.dev

.PHONY: logs
## Examine the logs from the Cloud container
logs:
	gcloud beta run services logs read $(TARGET) \
		--limit=20 --project $(PROJECT_ID)

.PHONY: logs/stream
## Stream Cloud Run logs
logs/stream:
	gcloud beta run services logs tail $(TARGET) --project $(PROJECT_ID)

.PHONY: clean/cloud
## Delete Cloud Run service and container
clean/cloud:
	@echo "Stopping and deleting Cloud Run service"
	gcloud run services delete $(TARGET)
	@echo "Deleting container image from Registry"
	gcloud container images delete $(IMAGE_URI) --force-delete-tags
# gcloud artifacts repositories delete
	
## clean up debugging symbol files
.PHONY: clean
clean:
	rm -f bin/*.dwarf

## This help screen
help:
				@printf "Available targets:\n\n"
				@awk '/^[a-zA-Z\-\_0-9%:\\]+/ { \
          helpMessage = match(lastLine, /^## (.*)/); \
          if (helpMessage) { \
            helpCommand = $$1; \
            helpMessage = substr(lastLine, RSTART + 3, RLENGTH); \
      gsub("\\\\", "", helpCommand); \
      gsub(":+$$", "", helpCommand); \
            printf "  \x1b[32;01m%-35s\x1b[0m %s\n", helpCommand, helpMessage; \
          } \
        } \
        { lastLine = $$0 }' $(MAKEFILE_LIST) | sort -u
				@printf "\n"
