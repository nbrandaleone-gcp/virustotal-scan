# app.rb
#
# Author: Nick Brandaleone <nbrand@mac.com>
# Date: March, 2024
#
# Google Cloud Function that moves files between Google Cloud Storage Buckets
# based upon a score derived from a VirusTotal scan and API call

require "functions_framework"
require "google/cloud/storage"
  
require 'dotenv'
require "json"

puts('Starting application....')
Dotenv.load

# Logger levels: (FATAL, ERROR, WARN, INFO, DEBUG)
# Logger::DEBUG is default. logger.level = Logger::INFO

def copy_file source_bucket_name:, source_file_name:, destination_bucket_name:, destination_file_name:
  # The ID of the bucket the original object is in
  # source_bucket_name = "source-bucket-name"

  # The ID of the GCS object to copy
  # source_file_name = "source-file-name"

  # The ID of the bucket to copy the object to
  # destination_bucket_name = "destination-bucket-name"

  # The ID of the new GCS object
  # destination_file_name = "destination-file-name"

  project_id = ENV['project_id']
  storage = Google::Cloud::Storage.new(project_id: project_id)
  bucket  = storage.bucket source_bucket_name, skip_lookup: true
  file    = bucket.file source_file_name

  destination_bucket = storage.bucket destination_bucket_name
  destination_file   = file.copy destination_bucket.name, destination_file_name
end

def delete_file bucket_name:, file_name:
  # The ID of your GCS bucket
  # bucket_name = "your-unique-bucket-name"

  # The ID of your GCS object
  # file_name = "your-file-name"

  project_id = ENV['project_id']

  storage = Google::Cloud::Storage.new(project_id: project_id)
  bucket  = storage.bucket bucket_name, skip_lookup: true
  file    = bucket.file file_name

  file.delete

  logger.info "Deleted #{file.name}"  #logger.debug did not work, but logger.info does
end

# We will receive a POST, with a JSON data blob
FunctionsFramework.http "gcs_move_file" do |request|
  message = "I received a request: #{request.request_method} #{request.url}"
  logger.info "#{message} #{request.body.read}"
  bucket  = (request.body.rewind && JSON.parse(request.body.read)["bucket"] rescue nil)
  file    = (request.body.rewind && JSON.parse(request.body.read)["object"] rescue nil)
  score   = (request.body.rewind && JSON.parse(request.body.read)["score"] rescue nil)
  
  quarantine_bucket = ENV['quarantine_bucket']
  clean_bucket = ENV['clean_bucket']
  dest = score.to_i >= 3 ? quarantine_bucket : clean_bucket
   
  copy_file(source_bucket_name: bucket, source_file_name: file, 
            destination_bucket_name: dest, destination_file_name: file)
  delete_file(bucket_name: bucket, file_name: file)
  
  logger.info "File: #{file} copied from source: #{bucket} -> destination: #{dest}"
  "File: #{file} copied from source: #{bucket} -> destination: #{dest}"
end