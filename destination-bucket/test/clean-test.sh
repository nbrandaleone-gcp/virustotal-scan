curl --header "Content-Type: application/json" \
  --request POST \
  --data '{"bucket":"nbrandaleone-testing","object":"aviation-weather.jpg","score":"1"}' \
  http://localhost:8080/

# Delete copied over file, for repeated testing
# gsutil rm gs://nbrandaleone-clean/aviation-weather.jpg
