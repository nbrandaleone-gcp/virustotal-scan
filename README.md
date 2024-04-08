# README.md

This repo contains code and directions to set up a Google Cloud [Workflows](https://cloud.google.com/workflows?hl=en),
that integrates with [VirusTotal](https://www.virustotal.com/gui/home/upload) to scan files, and move them into
appropriate Storage Buckets. Two Cloud Functions,
written in [Ruby](https://www.ruby-lang.org/en/), do the various checks and API calls to VirusTotal in order
to determine if the files are safe. Once a determination has been made,
the file is moved into a "safe" or "quarantine" bucket. If we can't determine the status of the file,
we leave the in the original bucket.

Workflow architecture:
![Architectural diagram](./workflow-diagram.png)

> [!NOTE]
> This workflow assumes that the file in question has already been uploaded and scanned by VirusTotal. We are then moving the file into a bucket based upon the results of the scan. IRL, one should check to see if the file has been scanned, and if it has not, then upload it to the VirusTotal website. After some time (usually minutes), the results will become available.

## Cloud Functions and Functions Framework

Cloud Functions are meant to be small chunks of code that are typicall event-driven in nature. Google has created a web framework that simplifies the boilerplate of setting up a web-server for all supported Cloud Functions languages. For example, for Python, this is wrapper around [Flask](https://flask.palletsprojects.com/en/3.0.x/). Likewise, for Ruby, it is a wrapper around [Sinatra](https://sinatrarb.com/). I find Ruby particularly expressive, so I wrote these functions in Ruby, while leveraging [Functions Framework](https://cloud.google.com/functions/docs/functions-framework).

1. https://github.com/GoogleCloudPlatform/functions-framework
2. https://cloud.google.com/functions/docs/functions-framework-ruby

# Setup environment

0. Update .env file with project_id, secret manager key name and Google Storage Bucket names
1. Add VirusTotal API key into [Google Secrets Manager](https://cloud.google.com/security/products/secret-manager)
2. Create x3 Cloud Storage Buckets for project
3. Deploy Cloud Functions
4. Deploy Workflows
5. Create EventArc trigger to start Workflow

## Gotchas

- The Cloud Functions Service Account key must have permissions to read from Secrets Manager.
- The Cloud Functions Service Account key must also have permissions to read from an EventArc trigger (eventarc.eventReceive) and execute a Workflow (workflows.invoker).
- You must get your own Virus Total API key. A personal key can be obtained for free, but will have feature and traffic limitations.
- Ensure that your Google Cloud Storage Buckets are private, closed to Internet prying.

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
gsutil mb -c standard -l us-central1 gs://some-bucket

# File commands
gsutil ls gs://nbrandaleone-testing
gsutil cp *.txt gs://my-bucket
gsutil rm gs://bucket/kitten.png
gsutil hash -m gs://nbrandaleone-testing/bad-file.txt
```

> [!WARNING]
> Since the focus of this tutorial in on security, we deploy the cloud functions
> with internal access only. This secures the CF, so they can only be accessed from
> within your GCP VPC environment/network.  
>
> We do not use dedicated Service Accounts, but that is an 
> additional method of securing your CFs that should be considered for any 
> production workload

## Deploy a Cloud Function

```shell
gcloud functions deploy ruby-virus-scan \
--gen2 \
--runtime=ruby32 \
--region=us-central1 \
--entry-point=hello_http \
--source=. \
--trigger-http \
--ingress-settings=internal-only \
--allow-unauthenticated
```

### Use of environmental variables

Both Cloud Functions require environmental variables in order to work.

**ruby-virus-scan:**

| Env Variable | Purpose |
| -------- | ------- |
| project_id | GCP project id |
| secret_id   | Secrets Manager id for TotalVirus API key |
| version_id | Secrets Manager version number. Defaults to "1" |

_Example_
``` shell
project_id = "my_project"
secret_id = "my_secret"
version_id = "1"
```

**ruby-move-file:**

| Env Variable | Purpose |
| -------- | ------- |
| project-id | GCP project id |
| clean_bucket | Name of Storage Bucket |
| quarantine_bucket | Name of Storage Bucket |

_Example_
```shell
clean_bucket = "my-bucket"
quarantine_bucket = "bad-bucket"
```

These evironmental variables can be injected into the runtime environment at deploy time.
Or, they can be written into a file called ".env" in the root directory of both functions.

```shell
# .env file
project_id = "my_cloud_project"
...
```

Or, via runtime injection:

```shell
gcloud functions deploy FUNCTION_NAME --set-env-vars FOO=bar,BAZ=boo FLAGS...
```

## Create a Workflow

```shell
gcloud workflows deploy scan-workflow --source=workflow.yaml
gcloud workflows executions list scan-workflow --limit=5

```

## Create an EventArc trigger

```shell
gcloud eventarc triggers create storage-events-trigger \
 --destination-workflow=scan-workflow \
 --event-filters="type=google.cloud.storage.object.v1.finalized" \
 --event-filters="bucket=nbrandaleone-testing" \
 --service-account="161156519703-compute@developer.gserviceaccount.com"

gcloud eventarc triggers list
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

## Run Cloud Functions locally (Ruby Functions Framework)

This is useful for local testing, and is a feature built in to the Functions Framework
library.

```shell
bundle exec functions-framework-ruby --target hello_http
```

## Test using Rake

I have created a variety of testing scripts, which are managed via several Rakefiles.
Since these will have to be modified for your environment to be useful, I will
only show what can be done.  It will be up to you to leverage the Rakefile
if you decide to make code changes.

```shell
$ rake -T

rake default           # Default task
rake deploy            # Deploy ruby app.rb <ruby-virus-scan> to Google Cloud Functions
rake logs:stream       # Stream logs of ruby-virus-scan CF
rake logs:view[limit]  # View logs of ruby-virus-scan CF
rake start             # Start local functions_framework server on port 8080
rake test              # Reset test files, and test x3 logic paths (good, bad, unknown)
rake test:clean1       # Send 'empty-file.txt' to CF
rake test:clean2       # Send 'hello-world.txt' to CF
rake test:mt           # Minitest testing suite
rake test:quarantine   # Send 'bad-file.txt' to CF
rake test:unknown      # Send un-scanned file to CF
```

# Clean Up

Here are some commands to delete all the resources that we created:

```shell
# Cloud Functions
gcloud functions delete YOUR_FUNCTION_NAME --gen2 --region REGION

# Workflows
gcloud workflows delete scan-workflow

# Eventarc
gcloud eventarc triggers delete storage-events-trigger

# Delete a Storage Bucket
gsutil rb [-f] gs://<bucket_name>...
```

---

# References:

### Google Cloud documentation

- https://cloud.google.com/workflows/docs/overview
- https://cloud.google.com/eventarc/docs/workflows/quickstart-storage#yaml
- https://cloud.google.com/security/products/secret-manager
- https://cloud.google.com/eventarc/docs
- https://cloud.google.com/storage?hl=en
- https://cloud.google.com/logging?hl=en
- https://cloud.google.com/sdk/gcloud/reference/topic/gcloudignore

### Ruby libraries and information

- https://www.ruby-lang.org/en/
- https://rubystyle.guide/
- https://googlecloudplatform.github.io/functions-framework-ruby/v1.4.1/index.html
- https://bundler.io/
- https://github.com/rbenv/rbenv
- https://ruby.github.io/rake/doc/rakefile_rdoc.html
- https://minitest.rubystyle.guide/#introduction
- https://runfile.dannyb.co/
- https://chrisseaton.com/truffleruby/

### Workflows cheat-sheet

- https://cloud.google.com/workflows/docs/reference/syntax/syntax-cheat-sheet

### Malware test file

- https://www.eicar.org/download-anti-malware-testfile/
- An empty file is considered 'good' in all cases.

### Similar blog

- https://medium.com/kpmg-uk-engineering/usecase-3-implement-a-cloud-function-to-scan-google-cloud-storage-data-with-virustotal-api-prior-c5d0348e6f32
