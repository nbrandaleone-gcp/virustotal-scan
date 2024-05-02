curl --header "Content-Type: application/json" \
  --request POST \
  --data '{"bucket":"nbrandaleone-testing","object":"hello-world.txt","callback_url":""}' \
  http://localhost:8080/
