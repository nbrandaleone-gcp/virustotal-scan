# app.rb
#
# Author: Nick Brandaleone <nbrand@mac.com>
# Date: March, 2024
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

# TODO: logger.info may be setup by Functions Framework. Check.
# TODO: Proper function comments

puts('Starting application....')
Dotenv.load
$debug = true
$log = Logger.new(STDOUT)
$log.level = Logger::DEBUG  # (FATAL, ERROR, WARN, INFO, DEBUG)

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

	# Return the secret payload.
	payload = version.payload.data
	$log.debug "APIKEY: #{payload}"
	payload
end

# Not needed anymore, since we can get MD5 hash from Storage Bucket metadata
def generate_hash(file)
	file_hash = Digest::MD5.hexdigest(File.read(file))     #=> "90015098..."
	$log.debug "File hash: #{file_hash}"
	file_hash
end

# Helper functions converting Google Storage Bucket hash to format used by TotalVirus
# Google format: file -> md5 hash (in hex) -> binary digits -> Base64 encoded
def decode64(bin)
	bin.unpack("m")
end

def bin_to_decimal(bin)
	bin.first.unpack("C*")
end

def to_hex(arr)
	arr.map { |d| d.to_s(16).upcase.rjust(2, '0') }.join
end

# Get the md5 hash from the Google Storage Bucket metadata for bucket/file
# It is also possible to get this from the initiating EventArc trigger data block
def get_md5(md5_hash)  # was (bucket, file)
#  project_id = ENV["project-id"]
#	storage = Google::Cloud::Storage.new(project_id: project_id)
#	bucket = storage.bucket bucket
#	file_ref = bucket.file file
#	md5_hash = file_ref.md5
#	$log.debug "MD5: #{md5_hash}"
	if md5_hash.empty? || md5_hash.nil?
		warn "Did not get valid MD5 from Google Cloud Storage metadata. Terminating..."
		exit 1
	end
	unpacked_md5 = md5_hash
		.then { decode64 _1 }
		.then { bin_to_decimal _1 }
		.then { to_hex _1 }
	$log.debug "Decoded MD5: #{unpacked_md5}"
	unpacked_md5
end

# Call VirusTotal API, and get report on file, using hash as identifier
def get_virustotal_report(file_hash)
	base = Addressable::URI.parse("https://www.virustotal.com/api/v3/files/")
	uri = base + file_hash
	apikey = get_secret_apikey
	headers = {Accept: 'application/json', 'x-apikey': apikey}
	begin
		res = Net::HTTP.get_response(uri, headers)
    warn "VirusTotal Headers: #{res.to_hash.inspect}"
	  res.body
	rescue Exception => error
		$log.debug "Error connecting to Virus Total."
    warn error.message
	end
end

# Parse response fields to determine if bucket/file is safe or not
def file_danger
end

# Simplify web server construction using Google Functions Framework
# We will receive a POST, with a JSON data blob
# {"bucket":"nbrandaleone-testing","object":"aviation-weather.jpg"}
FunctionsFramework.http "hello_http" do |request|
  # The request parameter is a Rack::Request object.
  # See https://www.rubydoc.info/gems/rack/Rack/Request
  message = "I received a request: #{request.request_method} #{request.url}"
  $log.info message
  $log.info request.body.read
  bucket  = (request.body.rewind && JSON.parse(request.body.read)["bucket"] rescue nil)
  file    = (request.body.rewind && JSON.parse(request.body.read)["object"] rescue nil)
  md5hash = (request.body.rewind && JSON.parse(request.body.read)["md5hash"] rescue nil)
  #name = request.params["name"] ||
  #		 (request.body.rewind && JSON.parse(request.body.read)["name"] rescue nil) ||

  md5 = get_md5(md5hash)
  response = get_virustotal_report(md5)
  $log.info response
  "Bucket: #{bucket}, File: #{file}, MD5: #{md5}"
  #"Hello #{CGI.escape_html name}!"
end
