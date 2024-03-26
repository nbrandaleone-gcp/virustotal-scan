# Rakfile

desc "Run all tests"
task default: %w[test:good test:bad test:unknown]

namespace "worflows" do
  desc "Deploy to Workflows"
  task :workflow do
    sh "gcloud workflows deploy scan-deploy --source=workflow.yaml"
  end
  
  desc "Delete Workflows"
  task :rm do
    sh "gcloud workflows delete scan-deploy"
  end
end

namespace "trigger" do
  desc "Describe EventArc trigger"
  task :info do
    sh "gcloud eventarc triggers describe storage-events-trigger"
  end
  
  desc "Delete trigger"
  task :rm do
    sh "gcloud eventarc triggers delete scan-deploy"
  end
  
  desc "Add EventArc trigger to bucket 'nbrandaleone-testing'"
  task :add do
    puts "not implemented"
  end
end

namespace "test" do
  desc "Copy 'bad' file into primary bucket"
  task :bad do
    sh "gsutil cp test-files/bad-file.txt gs://nbrandaleone-testing/"
  end

  desc "Copy 'good' file into primary bucket"
  task :good do
    sh "gsutil cp test-files/empty-file.txt gs://nbrandaleone-testing/"
    sh "gsutil cp test-files/hello-world.txt gs://nbrandaleone-testing/"
  end

  desc "Copy 'unknown' file into primary bucket"
  task :unknown do
    sh "gsutil cp test-files/aviation-weather.jpg gs://nbrandaleone-testing/"
  end
end
