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

puts('Starting application....')
Dotenv.load

# Logger levels: (FATAL, ERROR, WARN, INFO, DEBUG)
# puts -> STDOUT. warn -> STDERR
# logger.debug did not work, but logger.info does. Included in Functions Framework

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
      puts e.message
      return
  end

  begin
    project_id = ENV['project_id']
    storage = Google::Cloud::Storage.new(project_id: project_id)
    bucket  = storage.bucket source_bucket_name, skip_lookup: true
    destination_bucket = storage.bucket destination_bucket_name
    file    = bucket.file source_file_name

    if file.nil?
      logger.info "ERROR: File does not exist in source bucket"
      return
    else
      destination_file   = file.copy destination_bucket.name, destination_file_name
    end
  rescue
    logger.info "ERROR: Could not copy file from source to destination bucket."
  end
end

def delete_file bucket_name:, file_name:
  # The ID of your GCS bucket
  # bucket_name = "your-unique-bucket-name"

  # The ID of your GCS object
  # file_name = "your-file-name"

  project_id = ENV['project_id']

  begin
    unless [bucket_name, file_name].all?
      raise StandardError, "delete_file: 1 or more parameters are nil"
    end
  rescue StandardError => e
    puts e.message
    return
  end
    
  begin
    storage = Google::Cloud::Storage.new(project_id: project_id)
    bucket  = storage.bucket bucket_name, skip_lookup: true
    file    = bucket.file file_name

    if file.nil?
      logger.info "ERROR: File does not exist in source bucket"
      return
    else
      file.delete
    end
  rescue Google::Cloud::NotFoundError
    logger.info "ERROR: File not found. Not possible to delete it"
    end
end

def move_and_delete(sb, sf, db, df)
  copy_file(source_bucket_name: sb, source_file_name: sf, 
            destination_bucket_name: db, destination_file_name: df)
  delete_file(bucket_name: sb, file_name: sf)
  logger.info "File: #{sf} moved from source: #{sb} -> destination: #{db}"
end

# We will receive a POST, with a JSON data blob
FunctionsFramework.http "gcs_move_file" do |request|
  message = "I received a request: #{request.request_method} #{request.url}"
  logger.info "#{message}. Body: #{request.body.read}"

  bucket  = (request.body.rewind && JSON.parse(request.body.read)["bucket"] rescue nil)
  file    = (request.body.rewind && JSON.parse(request.body.read)["object"] rescue nil)
  score_p = (request.body.rewind && JSON.parse(request.body.read)["score"]  rescue nil)
  
  quarantine_bucket = ENV['quarantine_bucket']
  clean_bucket = ENV['clean_bucket']
  score = score_p.to_i

  if score < 0                          # unknown status. Private Scan recommended
    logger.info "File is unscanned. File left in original location."
    res = "File is unscanned. File left in original location."
  elsif score >= 0 && score < 3         # clean file
    move_and_delete(bucket, file, clean_bucket, file)
    res = "File: #{file} moved from source: #{bucket} -> destination: #{clean_bucket}"
  elsif score >= 3                      # dangerous file
    move_and_delete(bucket, file, quarantine_bucket, file)
    res = "File: #{file} moved from source: #{bucket} -> destination: #{quarantine_bucket}"
  else
    logger.info "ERROR: Score #{score} is not a valid number"
    res = "Error determining score. File left in original location."
  end
  res
end