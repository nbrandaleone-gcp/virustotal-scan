# md5_helper.rb
# 
# Helper functions converting Google Storage Bucket hash to format used by TotalVirus
#

require 'digest'

# Not needed anymore, since we can get MD5 hash from Storage Bucket metadata
# Generate MD5 hash for a local file
def generate_hash(file)
	file_hash = Digest::MD5.hexdigest(File.read(file))     #=> "90015098..."
  if DEBUG
	  $log.debug "File hash: #{file_hash}"
  end
	file_hash
  
  # Query Cloud Storage for MD5 hash
  #
  # project_id = ENV["project-id"]
  #	storage = Google::Cloud::Storage.new(project_id: project_id)
  #	bucket = storage.bucket bucket
  #	file_ref = bucket.file file
  #	md5_hash = file_ref.md5
  #	$log.debug "MD5: #{md5_hash}"
end

################################################################################

# Google format: file -> md5 hash (in hex) -> binary digits -> Base64 encoded
def decode64(bin)
	bin.unpack("m")
  # I found an alternate way.
  # require 'base64'
  # name = Base64.decode64 event.data["message"]["data"] rescue "World"
end

def bin_to_decimal(bin)
	bin.first.unpack("C*")
end

def to_hex(arr)
	arr.map { |d| d.to_s(16).upcase.rjust(2, '0') }.join
end

# Get the md5 hash from the initiating EventArc data block
def get_md5(md5_hash)  # was (bucket, file)
	if md5_hash.empty? || md5_hash.nil?
		warn "Did not get valid MD5 from Google Cloud Storage metadata. Terminating..."
		exit 1
	end
  
	unpacked_md5 = md5_hash
		.then { decode64 _1 }
		.then { bin_to_decimal _1 }
		.then { to_hex _1 }
end