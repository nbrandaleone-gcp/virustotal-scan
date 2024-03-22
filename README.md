# README.md

This repo contains code and directions to set up a Google Cloud Workflow,
that integrates with VirusTotal to scan files, and move them into
appropriate Storage Buckets. Two Cloud Functions,
written in Ruby, do the various checks and API calls to VirusTotal in order
to determine if the files are safe. Once a determination has been made,
the file is moved into a "safe" or "quarantine" bucket.

Worflow architecture:
![architectural diagram](https://github.com/nbrandaleone-gcp/virustotal-scan/workflor-diagram.png "diagram")

## Workflow cheat-sheet

https://cloud.google.com/workflows/docs/reference/syntax/syntax-cheat-sheet

## Copy file up to GCS

gcloud storage cp bad-file.txt gs://nbrandaleone-testing/bad-file.txt
gcloud storage rm gs://nbrandaleone-testing/bad-file.txt

## Google Secret Manager

gcloud secrets create secret-id \
 --replication-policy="automatic"

gcloud secrets versions access version-id --secret="secret-id"

## Malware test file

https://www.eicar.org/download-anti-malware-testfile/

# Create workflow

gcloud workflows deploy scan-workflow --source=workflow.yaml
gcloud workflows executions list ${MY_WORKFLOW} --limit=5
gcloud workflows delete scan-workflow

# Create EventArc trigger

gcloud eventarc triggers create storage-events-trigger \
 --destination-workflow=scan-workflow \
 --event-filters="type=google.cloud.storage.object.v1.finalized" \
 --event-filters="bucket=nbrandaleone-testing" \
 --service-account="161156519703-compute@developer.gserviceaccount.com"

gcloud eventarc triggers delete storage-events-trigger

## Delete function

gcloud functions delete YOUR_FUNCTION_NAME --gen2 --region REGION

# Assign IAM permissions to default compute SA

gcloud projects add-iam-policy-binding testing-355714 \
 --member=serviceAccount:161156519703-compute@developer.gserviceaccount.com \
 --role=roles/eventarc.eventReceiver

gcloud projects add-iam-policy-binding testing-355714 \
 --member=serviceAccount:161156519703-compute@developer.gserviceaccount.com \
 --role=roles/workflows.invoker

gcloud projects add-iam-policy-binding testing-355714 \
 --member=serviceAccount:161156519703-compute@developer.gserviceaccount.com \
 --role=roles/logging.logWriter

SERVICE_ACCOUNT="$(gsutil kms serviceaccount -p testing-355714)"

gcloud projects add-iam-policy-binding testing-355714 \
 --member="serviceAccount:${SERVICE_ACCOUNT}" \
 --role='roles/pubsub.publisher'

gcloud projects add-iam-policy-binding testing-355714 \
 --member=serviceAccount:service-161156519703@gcp-sa-pubsub.iam.gserviceaccount.com \
 --role=roles/iam.serviceAccountTokenCreator

# References:

- https://cloud.google.com/eventarc/docs/workflows/quickstart-storage#yaml
-
