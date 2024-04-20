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
require "google/cloud/secret_manager"

require "addressable"   # https://github.com/sporkmonger/addressable
require 'net/http'
require "rest-client"   # https://github.com/rest-client/rest-client
require "logger"
require "json"
require 'dotenv'

#FunctionsFramework.on_startup do
#  require_relative "lib/md5_helper"
#end

puts('Starting application private-upload ...')

# Dotenv - loads environmental variables.
# Intended for Development only. However, due to Cloud Function lifecycle,
# which forces a rebuild during every deploy, it can work in Production as well.
Dotenv.load 

# Any value will make DEBUG true
DEBUG = ENV["DEBUG"] || false
$log = Logger.new(STDOUT)       # $log is a global variable
DEBUG == true ? $log.level = Logger::DEBUG : $log.level = Logger::INFO

# Get VirusTotal API key securely via Google Secrets Manager
def get_secret_apikey
  # Env.fetch("MY_VAR") raises exception if no ENV variable exists
  project_id = ENV["project_id"]
  secret_id  = ENV["secret_id"]
  version_id = ENV["version_id"] || "1"
  
  if project_id.nil? || secret_id.nil?
    $log.debug "ERROR: environmental variables are not set properly. Terminating..."
    exit(1)
  end
  if DEBUG
    $log.debug "project_id: #{project_id}"
    $log.debug "secret_id: #{secret_id}"
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
		$log.debug "ERROR: Can't access Google Secrets Manager. Terminating..."
		exit(1)
	end

	# Return the secret payload
	version.payload.data
end

# Call VirusTotal private API, and get report on file, using hash as identifier
def get_virustotal_report(file_hash)
	base = Addressable::URI.parse("https://www.virustotal.com/api/v3/private/files/")
	uri = base + file_hash
	apikey = get_secret_apikey
	headers = {Accept: 'application/json', 'x-apikey': apikey}
  
  http = NET::HTTP.new(uri)
  
  request = NET::HTTP::Post.new(uri)
  request["accept"] = 'application/json'
  request["content-type"] = 'multipart/form-data; boundary=---011000010111000001101001'
  request.body = "-----011000010111000001101001\r\nContent-Disposition: form-data; name=\"disable_sandbox\"\r\n\r\nfalse\r\n-----011000010111000001101001\r\nContent-Disposition: form-data; name=\"enable_internet\"\r\n\r\nfalse\r\n-----011000010111000001101001\r\nContent-Disposition: form-data; name=\"intercept_tls\"\r\n\r\nfalse\r\n-----011000010111000001101001--"
  
  response = http.request(request)
  puts response.read_body
  # res = Net::HTTP.start(hostname) do |http|
  # http.request(req)
  # end
  
  # data = '{"userId": 1, "id": 1, "title": "delectus aut autem", "completed": false}'
  # http = Net::HTTP.new(hostname)
  # http.post('/todos', data) do |res|
  #   p res
  # end # => #<Net::HTTPCreated 201 Created readbody=true>
  
	begin
	  res = Net::HTTP.get_response(uri, headers)
	  res.body
	rescue Exception => error
		$log.debug "Error connecting to Virus Total."
    $log.debug error.message
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

def list_files
  if DEBUG
    p Dir["./*"]
    p Dir["/bucket/*"]
    $log.debug "Files: #{Dir["/bucket/*"]}"
  end
  
  # Dir.entries("your/folder").select { |f| File.file? File.join("your/folder", f) }
  Dir["/bucket/*"]
end

FunctionsFramework.http "hello_http" do |request|
  # FunctionFramework has a global logger object, and local object
  message = "I received a request: #{request.request_method} from #{request.url}"
  request.logger.info "#{message}. Body: #{request.body.read}"
  warn "Testing 1, 2, 3"   # warn is a shortcut
  bucket  = (request.body.rewind && JSON.parse(request.body.read)["bucket"]  rescue nil)
  file    = (request.body.rewind && JSON.parse(request.body.read)["object"]  rescue nil)
  md5hash = (request.body.rewind && JSON.parse(request.body.read)["md5hash"] rescue nil)

  # TODO: We should validate the input from the EventArc trigger
  # md5 = get_md5(md5hash)
  files = list_files()
  #vt_report = get_virustotal_report(md5)
  #score = get_score(vt_report)
  # $log.info "Bucket: #{bucket}, File: #{file}, MD5: #{md5}, Score: #{score}"
  logger.info "Bucket: #{bucket}, File: #{files}" # Global FF

  #{ 'bucket': bucket, 'object': file, 'score': score.to_s }
  { 'files': files }
end
