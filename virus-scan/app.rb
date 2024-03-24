# app.rb
#
# Author: Nick Brandaleone <nbrand@mac.com>
# Date: March 2024
#
# Google Cloud Function that leverages Virus Total to scan files dropped
# into Google Cloud Storage buckets.

require "functions_framework"
require "google/cloud/secret_manager"
require "google/cloud/storage"

require "addressable"
require "logger"
require "cgi"
require "json"
require 'uri'
require 'net/http'
require 'digest'
require 'dotenv'

FunctionsFramework.on_startup do
  require_relative "lib/md5_helper"
end

# TODO: Proper function comments using 

puts('Starting application....')

# Dotenv - loads environmental variables.
# Intended for Development only. However, due to Cloud Function lifecycle,
# which forces a rebuild during every deploy, it can work in Production as well.
Dotenv.load 

$log = Logger.new(STDOUT)
$log.level = Logger::INFO  # (FATAL, ERROR, WARN, INFO, DEBUG)

# Get VirusTotal API key securely via Google Secrets Manager
def get_secret_apikey
  project_id = ENV["project_id"]
  secret_id  = ENV["secret_id"]
	version_id = "1"
  $log.debug "project_id: #{project_id}"
  $log.debug "secret_id: #{secret_id}"

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
		$log.debug "ERROR: Can't access Google Secrets Manager. Terminating..."
		exit(1)
	end

	# Return the secret payload
	version.payload.data
end

# Call VirusTotal API, and get report on file, using hash as identifier
def get_virustotal_report(file_hash)
	base = Addressable::URI.parse("https://www.virustotal.com/api/v3/files/")
	uri = base + file_hash
	apikey = get_secret_apikey
	headers = {Accept: 'application/json', 'x-apikey': apikey}
	begin
	  res = Net::HTTP.get_response(uri, headers)
	  res.body
	rescue Exception => error
		$log.debug "Error connecting to Virus Total."
    warn error.message
	end
end

# Parse response fields looking for 'malicous' stats
def get_score(vt_report)
  begin
    json = JSON.parse(vt_report)
    score = json['data']['attributes']['last_analysis_stats']['malicious']
    $log.debug "Malicious score: #{score}"
    score
  rescue => e
    warn "Unable to parse JSON"
    warn e
    -1      # flag indicating not able to parse. Most likely unknown to VirusTotal
  end
end

# We will receive a POST, with a JSON data blob
FunctionsFramework.http "hello_http" do |request|
  # The request parameter is a Rack::Request object.
  # See https://www.rubydoc.info/gems/rack/Rack/Request

  message = "I received a request: #{request.request_method} #{request.url}"
  $log.info "#{message}. Body: #{request.body.read}"
  bucket  = (request.body.rewind && JSON.parse(request.body.read)["bucket"]  rescue nil)
  file    = (request.body.rewind && JSON.parse(request.body.read)["object"]  rescue nil)
  md5hash = (request.body.rewind && JSON.parse(request.body.read)["md5hash"] rescue nil)

  md5 = get_md5(md5hash)
  vt_report = get_virustotal_report(md5)
  score = get_score(vt_report)
  $log.info "Bucket: #{bucket}, File: #{file}, MD5: #{md5}, Score: #{score}"

  { 'bucket': bucket, 'object': file, 'score': score.to_s }
end
