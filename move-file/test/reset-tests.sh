gsutil cp ../../test-files/bad-file.txt gs://nbrandaleone-testing/
gsutil cp ../../test-files/aviation-weather.jpg gs://nbrandaleone-testing/

gsutil rm gs://nbrandaleone-clean/aviation-weather.jpg
gsutil rm gs://nbrandaleone-quarantine/bad-file.txt

gsutil ls gs://nbrandaleone-testing/
gsutil ls gs://nbrandaleone-clean/
gsutil ls gs://nbrandaleone-quarantine/

