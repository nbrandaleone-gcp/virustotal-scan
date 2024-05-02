curl --header "Content-Type: application/json" \
  --request POST \
  --data '{"bucket":"nbrandaleone-testing","object":"hello-world.txt","score":"0"}' \
  http://localhost:8080/

# Delete copied file, for repeated testing
# gsutil rm gs://nbrandaleone-quarantine/bad-file.txt
