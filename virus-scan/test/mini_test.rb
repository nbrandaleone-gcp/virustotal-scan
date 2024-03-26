require "minitest/autorun"
require "functions_framework/testing"

class MyTest < Minitest::Test
  include FunctionsFramework::Testing

  def test_http_function
    load_temporary "app.rb" do
      request = make_post_request("http://localhost:8080", 
        "{\"bucket\":\"nbrandaleone-testing\",\"object\":\"bad-file.txt\",\"md5hash\":\"aWMORXTsZ5gjmwkc2kPcoA==\"}", 
        ["Content-Type: application/json"])
      response = call_http "hello_http", request
      assert_equal 200, response.status
      assert_equal "application/json; charset=utf-8", response.content_type
      parsed_response = JSON.parse(response.body.join)
      assert_equal 'nbrandaleone-testing', parsed_response['bucket']
      assert_equal 'bad-file.txt', parsed_response['object']
      assert_match(/\d+/, parsed_response['score'])
    end
  end

  def test_missing_filename
    load_temporary "app.rb" do
      request = make_post_request("http://localhost:8080", 
        "{\"bucket\":\"nbrandaleone-testing\"}",
        ["Content-Type: application/json"])
      response = call_http "hello_http", request
      assert_equal 500, response.status
#      assert_equal("File is unscanned. File left in original location.", 
#        response.body.join)
    end
  end
end
