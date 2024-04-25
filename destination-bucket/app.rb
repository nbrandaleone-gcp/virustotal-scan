# app.rb
#
# Author: Nick Brandaleone <nbrand@mac.com>
# Date: March 2024
#
# Google Cloud Function that moves files between Google Cloud Storage Buckets
# based upon a score derived from a VirusTotal scan and API call

require "functions_framework"
require "google/cloud/storage"
  
require 'dotenv'
require "json"

FunctionsFramework.on_startup do
  logger.info('Starting application gcs-move-file ...')
  Dotenv.load
  
  # Any value will make DEBUG true.
  DEBUG = ENV["DEBUG"] || false
  if DEBUG
    logger.debug!
    logger.debug "DEBUG is true"  # warn is a Kernel method, shortcut for STDERR
  else
    logger.info "DEBUG is false"
  end
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
  begin
    unless [source_bucket_name, source_file_name, destination_bucket_name, destination_file_name].all?
      raise StandardError, "copy_file: 1 or more parameters are nil"
    end
  rescue StandardError => e
      logger.info e.message
      exit(1)
  end

  project_id = ENV['project_id']
  storage = Google::Cloud::Storage.new(project_id: project_id)
  bucket  = storage.bucket source_bucket_name, skip_lookup: true
  destination_bucket = storage.bucket destination_bucket_name
  file    = bucket.file source_file_name

  if !file.exists?
    logger.info "ERROR: File does not exist in source bucket"
    exit(1)
  else
    destination_file   = file.copy destination_bucket.name, destination_file_name
    logger.info "Copying file: #{source_file_name} from bucket: #{source_bucket_name} to bucket: #{destination_bucket_name}"
  end
  if !destination_file.exists?
    logger.info "ERROR: File was not copied to destination bucket properly."
    logger.info "destination bucket: #{destination_bucket_name}, file: #{destination_file_name}"
    exit(1)
  end
end

def delete_file bucket_name:, file_name:
  # The ID of your GCS bucket
  # bucket_name = "your-unique-bucket-name"

  # The ID of your GCS object
  # file_name = "your-file-name"

  project_id = ENV['project_id']

  begin
    unless [bucket_name, file_name, project_id].all?
      raise StandardError, "delete_file: 1 or more parameters are nil"
    end
  rescue StandardError => e
    logger.info e.message
    exit(1)
  end
    
  storage = Google::Cloud::Storage.new(project_id: project_id)
  bucket  = storage.bucket bucket_name, skip_lookup: true
  file    = bucket.file file_name

  if file.exists?
    file.delete
    logger.info "Deleting file: #{file_name}, from bucket: #{bucket_name}"
  else
    logger.info "ERROR: File does not exist in source bucket"
    exit(1)
  end
end

def move_and_delete(sb, sf, db, df)
  copy_file(source_bucket_name: sb, source_file_name: sf, 
            destination_bucket_name: db, destination_file_name: df)
  delete_file(bucket_name: sb, file_name: sf)
end

FunctionsFramework.http "gcs_move_file" do |request|
  message = "I received a request: #{request.request_method} #{request.url}"
  logger.info "#{message}. Body: #{request.body.read}"

  bucket  = (request.body.rewind && JSON.parse(request.body.read)["bucket"] rescue nil)
  file    = (request.body.rewind && JSON.parse(request.body.read)["object"] rescue nil)
  score_p = (request.body.rewind && JSON.parse(request.body.read)["score"]  rescue nil)
  
  quarantine_bucket = ENV['quarantine_bucket']
  clean_bucket = ENV['clean_bucket']
  
  # TODO: move error checks to start-up block. Confirm global scope.
  begin
    unless [quarantine_bucket, clean_bucket, score_p].all?
      raise StandardError, "FF.request: 1 or more parameters or ENV variables are nil"
    end
  rescue StandardError => e
    logger.info e.message
    exit(1)
  end

  score = score_p.to_i  # score is passed as a string. Convert to int
  if score < 0                          # unknown status. Private Scan recommended
    logger.info "File is unscanned. Recommend private scan."
    res = "File is unscanned and has unknown status."
  elsif score >= 0 && score < 3         # clean file
    move_and_delete(bucket, file, clean_bucket, file)
    res = "File: #{file} moved from source: #{bucket} -> destination: #{clean_bucket}"
  elsif score >= 3                      # dangerous file. Score goes up to 70
    move_and_delete(bucket, file, quarantine_bucket, file)
    res = "File: #{file} moved from source: #{bucket} -> destination: #{quarantine_bucket}"
  else
    logger.info "ERROR: Score #{score} is not a valid number"
    res = "Error determining score. File left in original location."
  end
  
  res
end