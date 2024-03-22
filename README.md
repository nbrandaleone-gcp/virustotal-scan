# README.md

This repo contains code and directions to set up a Google Cloud Workflow,
that integrates with VirusTotal to scan files, and move them into
appropriate Storage Buckets. Two Cloud Functions,
written in Ruby, do the various checks and API calls to VirusTotal in order
to determine if the files are safe. Once a determination has been made,
the file is moved into a "safe" or "quarantine" bucket.

Workflow architecture:
![Architectural diagram](./workflow-diagram.png)

## Workflow cheat-sheet

https://cloud.google.com/workflows/docs/reference/syntax/syntax-cheat-sheet

# Setup environment - Big Picture

1. Add VirusTotal API key into [Google Secrets Manager](https://cloud.google.com/security/products/secret-manager)
2. Create x3 Cloud Storage Bucket for project
3. Deploy Cloud Functions
4. Deploy Workflow
5. Create EventArc trigger to start Workflow

## Gotchas

- The Cloud Functions Service Account key must have permissions to read from Secrets Manager.
- The Cloud Functions Service Account key must also have permissions to read from an EventArc trigger (eventarc.eventReceive) and execute a Workflow (workflows.invoker).
- You must get your own Virus Total API key. A personal key can be obtained for free, but will have feature and traffic limitations.
- This project uses public Storage Buckets for educations purposes. These settings should be locked down for any production purposes.

# How to:

## Create a secret in Google Secrets Manager

```shell
gcloud secrets create secret-id \
 --replication-policy="automatic"

gcloud secrets versions access version-id --secret="secret-id"
```

## Copy a file into a GCS bucket via CLI

```shell
# Create a bucket
gcloud storage buckets create gs://my-bucket gs://my-other-bucket

# Move and delete files
gcloud storage cp bad-file.txt gs://nbrandaleone-testing/bad-file.txt
gcloud storage rm gs://nbrandaleone-testing/bad-file.txt
```

## Deploy a Cloud Function

```shell
gcloud functions deploy ruby-virus-scan \
--gen2 \
--runtime=ruby32 \
--region=us-central1 \
--entry-point=hello_http \
--source=. \
--trigger-http \
--allow-unauthenticate

gcloud functions delete YOUR_FUNCTION_NAME --gen2 --region REGION
```

## Create a Workflow

```shell
gcloud workflows deploy scan-workflow --source=workflow.yaml
gcloud workflows executions list ${MY_WORKFLOW} --limit=5
gcloud workflows delete scan-workflow
```

## Create an EventArc trigger

```shell
gcloud eventarc triggers create storage-events-trigger \
 --destination-workflow=scan-workflow \
 --event-filters="type=google.cloud.storage.object.v1.finalized" \
 --event-filters="bucket=nbrandaleone-testing" \
 --service-account="161156519703-compute@developer.gserviceaccount.com"

gcloud eventarc triggers delete storage-events-trigger
```

## Test Cloud Functions locally (Ruby Functions Framework)

```shell
bundle exec functions-framework-ruby --target hello_http
```

## View Google Logs

```shell
gcloud functions logs read ruby-virus-scan --limit=10

gcloud beta run services logs read my-service --log-filter="severity>=ERROR"

gcloud beta run services logs read my-service --log-filter='timestamp<="2015-05-31T23:59:59Z" AND
 timestamp>="2015-05-31T00:00:00Z"'

 gcloud beta run services logs read my-service --log-filter="textPayload:SearchText" --limit=10 --format=json

 gcloud beta run services logs tail SERVICE --project PROJECT-I
```

---

# References:

- https://cloud.google.com/eventarc/docs/workflows/quickstart-storage#yaml
-

### Malware test file

https://www.eicar.org/download-anti-malware-testfile/
