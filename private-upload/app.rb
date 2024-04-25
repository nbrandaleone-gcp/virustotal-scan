# app.rb
#
# Author: Nick Brandaleone <nbrand@mac.com>
# Date: April 2024
#
# Google Cloud Function that leverages Virus Total to scan files dropped
# into Google Cloud Storage buckets.
#
# This function uses private scanning, for unknown files.

require "functions_framework"
require "google/cloud/storage"
require "google/cloud/secret_manager"

#require 'net/http'
require "rest-client"   # https://github.com/rest-client/rest-client
require "json"
require 'dotenv'

# Moving all init code into `on_startup' block
FunctionsFramework.on_startup do
  logger.info('Starting application private-upload ...')

  # Dotenv - loads environmental variables.
  # Intended for Development only. However, due to Cloud Function lifecycle,
  # which forces a rebuild during every deploy, it can work in Production as well.
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

# Get VirusTotal API key securely via Google Secrets Manager
def get_secret_apikey()
  # Env.fetch("MY_VAR") raises exception if no ENV variable exists
  project_id = ENV["project_id"]
  secret_id  = ENV["secret_id"]
  version_id = ENV["version_id"] || "1"
  
  if project_id.nil? || secret_id.nil?
    logger.info "ERROR: environmental variables are not set properly. Terminating..."
    exit(1)
  end

	# Create a Secret Manager client.
	client = Google::Cloud::SecretManager.secret_manager_service

	# Build the resource name of the secret version.
	name = client.secret_version_path(
	  project:        project_id,
	  secret:         secret_id,
	  secret_version: version_id
	)

	# Access the secret version.
	begin
		version = client.access_secret_version name: name
	rescue
		warn "ERROR: Can't access Google Secrets Manager. Terminating..."
		exit(1)
	end

	# Return the secret payload
	version.payload.data
end

# Call VirusTotal private API, and upload a file for scanning
# https://docs.virustotal.com/reference/post_files
# File must be less than 32MB. If larger, a different endpoint must be used.
def private_upload(file)
  url = "https://www.virustotal.com/api/v3/private/files"

  # I should get the secret key once, instead of for every http call
	apikey = get_secret_apikey()
	headers = { Accept: 'application/json', 'x-apikey': apikey }
  begin
      request = RestClient::Request.new({   # RestClient.post(...)
        :method => :post,
        :url => url,
        :payload => {
          :multipart => true,
          :file => File.new(file, 'rb'),
          :disable_sandbox => 'false',
          :enable_internet => 'false',
          :intercept_tls => 'false'
        }, 
        :headers => headers})
       
      response = request.execute 
      # Response.body is a string. https://www.rubydoc.info/gems/rest-client/2.1.0/RestClient/Response
      links_self = JSON.parse(response.body)["data"]["links"]["self"] 
      # Debugger
      # binding.irb
      
  rescue RestClient::ExceptionWithResponse => e
      logger.info "Error connecting to Virus Total."
      logger.info "HTTP status code #{e.response.code}"
      logger.info "Error message: #{e.response.body}"
  end
  
  # Return link to check on scan status
  links_self
end

# Check to see if the file has been scanned via VT Private Scanning
# https://docs.virustotal.com/reference/private-analysis
# Return true if status is complete. False otherwise.
def check_vt(url)
  #url = "https://www.virustotal.com/api/v3/private/analyses/{id}"
  apikey = get_secret_apikey()
  headers = { Accept: 'application/json', 'x-apikey': apikey }
  
  res = RestClient.get(url, headers)
  # FIXME: test JSON failure. Should I add rescue to all checks?
  #links_item = JSON.parse(res.body)["data"]["links"]["item"]
  scan_status = JSON.parse(res.body)["data"]["attributes"]["status"] rescue nil
  file_sha256 = JSON.parse(res.body)["meta"]["file_info"]["sha256"] rescue nil
  
  if DEBUG
    #logger.debug res
    #logger.debug "check_vt. SHA256 is: #{file_sha256}"
    logger.debug "check_vt. scan_status is: #{scan_status}"  
  end
  
  # scan_status will be "queued", "in-progress" or "completed"
  if scan_status == "completed" 
    return true, file_sha256
  else 
    return false, nil
  end
end

# Get the private scan report. Requires the files SHA-256 as the file ID.
# https://docs.virustotal.com/reference/private-files-info
def get_report(sha256)
  if sha256.nil?  # This is checked in the main function as well. Belt and Suspenders.
    logger.info "SHA256 is nil. Exiting ..."
    exit(1)
  end
  
  # It is also possible to generate SHA256 with the following 2 lines
  # require 'digest'
  # Digest::SHA256.hexdigest 'abc'        # => "ba7816bf8..."
  
  #url = "https://www.virustotal.com/api/v3/private/files/{id}"
  url = "https://www.virustotal.com/api/v3/private/files/" + sha256
  apikey = get_secret_apikey()
  headers = { Accept: 'application/json', 'x-apikey': apikey }
  
  res = RestClient.get(url, headers)
  JSON.parse(res.body)["data"]["attributes"]["threat_verdict"] rescue nil
end

def download_file(bucket, object)
  project_id = ENV["project_id"]
  
  begin
    unless [project_id, bucket, object].all?
      raise StandardError, "download_file: 1 or more parameters are nil"
    end
  rescue StandardError => e
    logger.info e.message
    exit(1)
  end
  
  storage = Google::Cloud::Storage.new(
    project_id: project_id
  )
  my_bucket = storage.bucket bucket
  
  if my_bucket.nil?
    logger.info "ERROR. download_file. Bucket #{bucket} does not exist"
    exit(1)
  end
  
  file = my_bucket.file object
  if file.nil?
    logger.info "ERROR. download_file. File #{object} does not exist in bucket #{bucket}."
    exit(1)
  end
  
  # Check to see if the file is under 32 MB in size
  if file.size > 30_000_000 # Approx 32 MB in bytes
    logger.info "ERROR. file size is too large to copy. Size: #{file.size}"
    exit(1)
  end
  
  # Copy file from bucket to local filesystem
  file_path = "/tmp/" + object
  file.download file_path
  file_path
end

FunctionsFramework.http "private_upload" do |request|
  # FunctionFramework has a global logger object, and local logger object
  # request.body is an I/O object, not a string. Thus, the rewind method
  message = "I received a request: #{request.request_method} from #{request.url}"
  request.logger.info "#{message}. Body: #{request.body.read}"
  bucket  = (request.body.rewind && JSON.parse(request.body.read)["bucket"]  rescue nil)
  file    = (request.body.rewind && JSON.parse(request.body.read)["object"]  rescue nil)
  
  # Download file from bucket, so it can be uploaded into VT private scan
  file_path = download_file(bucket, file)
  status_link = private_upload(file_path)
  
  # Sleep up to 50 minutes, waiting for scan to be completed
  # NOTE: Google Workflows has a  30 minute maximum timeout (5 minute default).
  # NOTE: Other architectures (callbacks, polling) allow for greater timeouts. 
  i = 0   
  while i < 10
    status, file_sha256 = check_vt(status_link)
    status ? break : i += 1
    sleep(5 * 60)  # 5 minutes per loop
  end
  
  # Get scan results
  # verdict can be: VERDICT_UNDETECTED, VERDICT_SUSPICIOUS, VERDICT_MALICIOUS
  verdict = "Threat Analysis failed"
  unless file_sha256.nil?
    verdict = get_report(file_sha256)
    logger.info verdict
  end
  
  # FIXME: Return result with artificial score, and kick off move function
  { 'threat_verdict': verdict }
end
