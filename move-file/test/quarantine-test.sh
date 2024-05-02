curl --header "Content-Type: application/json" \
  --request POST \
  --data '{"bucket":"nbrandaleone-testing","object":"bad-file.txt","score":"10"}' \
  http://localhost:8080/

# Delete copied file, for repeated testing
# gsutil rm gs://nbrandaleone-quarantine/bad-file.txt
