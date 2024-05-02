# trigger-job/app.rb
#
# Author: Nick Brandaleone <nbrand@mac.com>
# April 2024
#
# This Cloud Function asynchronously kicks off a Cloud Run Job.
# The Job must be already uploaded into the system, and is simply
# waiting for an execution command in order to begin.

require 'functions_framework'
require 'google/cloud/run/v2'
require 'dotenv'
require 'json'

FunctionsFramework.on_startup do
  logger.info('Starting application trigger_job ...')
  Dotenv.load
  
  DEBUG = ENV.fetch('DEBUG', false)
  if DEBUG
    logger.debug!
    logger.debug "DEBUG is true"  # warn is a Kernel method, shortcut for STDERR
  else
    logger.info "DEBUG is false"
  end
end

def execute_job(bucket, file, callback_url)
  # Create a client object. The client can be reused for multiple calls.
  client = Google::Cloud::Run::V2::Jobs::Client.new do |config|
    config.timeout = 10
  end

  # Grabbing Google Cloud information from ENV variables
  project = ENV.fetch('project_id', 'testing-355714')
  location = ENV.fetch('location', 'us-central1')
  parent="projects/#{project}/locations/#{location}"

  # Format: projects/{project}/locations/{location}/jobs/{job}, 
  # where {project} can be project id or number.
  job_name = parent + "/jobs/private-upload-job"

  # Create new ENV variables. Third field 'value_source', for secrets
  env1 = Google::Cloud::Run::V2::EnvVar.new name: "bucket", value: bucket
  env2 = Google::Cloud::Run::V2::EnvVar.new name: "object", value: file
  env3 = Google::Cloud::Run::V2::EnvVar.new name: "callback_url", value: callback_url

  if DEBUG
    logger.debug (p env1)
    logger.debug (p env2)
    logger.debug (p env3)
  end

  # Container Override
  # args[<String>], clear_args-> boolean, name<String> (DNS_LABEL)
  my_override = 
    Google::Cloud::Run::V2::RunJobRequest::Overrides::ContainerOverride.new(
      env: [env1, env2, env3]
    )

  # Job Override. Hash. 
  # timeout
  job_override = Google::Cloud::Run::V2::RunJobRequest::Overrides.new
  job_override = {task_count: 1, container_overrides: [my_override]}

  result = client.run_job(name: job_name, overrides: job_override)

  # return response if finished
  if result.response?
    logger.info result.response
  else
    logger.info "No response received yet."
  end

  rescue StandardError => e
    logger.info e.message
  ensure
    true
end

FunctionsFramework.http "trigger_job" do |request|
  message = "I received a request: #{request.request_method} #{request.url}"
  logger.info "#{message}. Body: #{request.body.read}"

  bucket  = (request.body.rewind && JSON.parse(request.body.read)["bucket"] rescue nil)
  file    = (request.body.rewind && JSON.parse(request.body.read)["object"] rescue nil)
  callback_url = (request.body.rewind && JSON.parse(request.body.read)["callback_url"]  rescue nil)

  execute_job(bucket, file, callback_url)

  "Cloud Run Job has been started"
end

######################## References ######################
# https://cloud.google.com/run/docs/reference/rpc/google.cloud.run.v2
#
# https://www.rubydoc.info/gems/google-cloud-run-v2/Google/Cloud/Run/V2/Jobs/Client
#
# https://cloud.google.com/ruby/docs/reference/google-cloud-run-v2/latest/
# Google-Cloud-Run-V2-Job
############################################################
