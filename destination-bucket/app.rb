# app.rb
#
# Author: Nick Brandaleone <nbrand@mac.com>
# Date: March, 2024
#
# Google Cloud Function that leverages Virus Total to scan files dropped
# into Google Cloud Storage buckets.

require "functions_framework"
require "google/cloud/storage"

require 'dotenv'
require "logger"
require "json"

puts('Starting application....')
Dotenv.load
$debug = true
$log = Logger.new(STDOUT)
$log.level = Logger::DEBUG  # (FATAL, ERROR, WARN, INFO, DEBUG)

# Test
# logger.info "Hello"

# Move to new function
def dangerous_gcs(bucket, file)
  quarantine_bucket = ENV['quarantine_bucket']
  clean_bucket = ENV['clean_bucket']
  hash = { 'source_bucket': bucket, 'dest_bucket': quarantine_bucket, 
           'file': file }
  $log.debug hash
  hash
end

def copy_file source_bucket_name:, source_file_name:, destination_bucket_name:, destination_file_name:
  # The ID of the bucket the original object is in
  # source_bucket_name = "source-bucket-name"

  # The ID of the GCS object to copy
  # source_file_name = "source-file-name"

  # The ID of the bucket to copy the object to
  # destination_bucket_name = "destination-bucket-name"

  # The ID of the new GCS object
  # destination_file_name = "destination-file-name"

  require "google/cloud/storage"

  storage = Google::Cloud::Storage.new
  bucket  = storage.bucket source_bucket_name, skip_lookup: true
  file    = bucket.file source_file_name

  destination_bucket = storage.bucket destination_bucket_name
  destination_file   = file.copy destination_bucket.name, destination_file_name

  puts "#{file.name} in #{bucket.name} copied to " \
       "#{destination_file.name} in #{destination_bucket.name}"
end

def delete_file bucket_name:, file_name:
  # The ID of your GCS bucket
  # bucket_name = "your-unique-bucket-name"

  # The ID of your GCS object
  # file_name = "your-file-name"

  require "google/cloud/storage"

  storage = Google::Cloud::Storage.new
  bucket  = storage.bucket bucket_name, skip_lookup: true
  file    = bucket.file file_name

  file.delete

  puts "Deleted #{file.name}"
end

def move_file bucket_name:, file_name:, new_name:
  # The ID of your GCS bucket
  # bucket_name = "your-unique-bucket-name"

  # The ID of your GCS object
  # file_name = "your-file-name"

  # The ID of your new GCS object
  # new_name = "your-new-file-name"

  require "google/cloud/storage"

  storage = Google::Cloud::Storage.new
  bucket  = storage.bucket bucket_name, skip_lookup: true
  file    = bucket.file file_name

  renamed_file = file.copy new_name

  file.delete

  puts "#{file_name} has been renamed to #{renamed_file.name}"
end
# [END storage_move_file]

if $PROGRAM_NAME == __FILE__
  move_file bucket_name: ARGV.shift, file_name: ARGV.shift, new_name: ARGV.shift
end

#  project_id = ENV["project-id"]
#	storage = Google::Cloud::Storage.new(project_id: project_id)
#	bucket = storage.bucket bucket
#	file_ref = bucket.file file
#	md5_hash = file_ref.md5
#	$log.debug "MD5: #{md5_hash}"

# We will receive a POST, with a JSON data blob
FunctionsFramework.http "hello_http" do |request|
  # The request parameter is a Rack::Request object.
  # See https://www.rubydoc.info/gems/rack/Rack/Request
  #name = request.params["name"] || (request.body.rewind && JSON.parse(request.body.read)["name"] rescue nil) ||
  message = "I received a request: #{request.request_method} #{request.url}"
  $log.info "#{message}\n #{request.body.read}"
  bucket  = (request.body.rewind && JSON.parse(request.body.read)["bucket"] rescue nil)
  file    = (request.body.rewind && JSON.parse(request.body.read)["object"] rescue nil)
  md5hash = (request.body.rewind && JSON.parse(request.body.read)["md5hash"] rescue nil)

  md5 = get_md5(md5hash)
  vt_report = get_virustotal_report(md5)
  score = get_score(vt_report)
  $log.info "Bucket: #{bucket}, File: #{file}, MD5: #{md5}, Score: #{score}"

  { 'source_bucket': bucket, 'file': file, 'score': score }
end