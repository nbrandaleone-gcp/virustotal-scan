require "minitest/autorun"
require "functions_framework/testing"

class MyTest < Minitest::Test
  include FunctionsFramework::Testing

  def test_http_function
    load_temporary "app.rb" do
      request = make_post_request("http://localhost:8080", 
        "{\"bucket\":\"nbrandaleone-testing\",\"object\":\"hello-world.txt\",\"score\":\"-1\"}",
        ["Content-Type: application/json"])
      response = call_http "gcs_move_file", request
      assert_equal 200, response.status
      assert_equal("File is unscanned. File left in original location.", 
        response.body.join)
    end
  end

  def test_missing_filename
    load_temporary "app.rb" do
      request = make_post_request("http://localhost:8080", 
        "{\"bucket\":\"nbrandaleone-testing\",\"score\":\"-1\"}",
        ["Content-Type: application/json"])
      response = call_http "gcs_move_file", request
      assert_equal 200, response.status
      assert_equal("File is unscanned. File left in original location.", 
        response.body.join)
    end
  end
end
