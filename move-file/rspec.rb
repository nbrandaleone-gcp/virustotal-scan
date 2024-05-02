require "rspec"
require "functions_framework/testing"
 
describe "functions_helloworld_get" do
  include FunctionsFramework::Testing
 
  it "generates the correct response body" do
    load_temporary "hello/app.rb" do
      request = make_get_request "http://example.com:8080/"
      response = call_http "hello_http", request
      expect(response.status).to eq 200
      expect(response.body.join).to eq "Hello Ruby!\n"
    end
  end
end
