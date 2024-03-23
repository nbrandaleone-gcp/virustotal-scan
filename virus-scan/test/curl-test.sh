curl --header "Content-Type: application/json" \
  --request POST \
  --data '{"bucket":"nbrandaleone-testing","object":"bad-file.txt","md5hash":"aWMORXTsZ5gjmwkc2kPcoA=="}' \
  http://localhost:8080/
