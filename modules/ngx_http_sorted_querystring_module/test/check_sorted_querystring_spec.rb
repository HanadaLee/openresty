require File.expand_path('spec_helper', File.dirname(__FILE__))

describe "check sorted querystring module" do
  it "should expose the querystring args ordered in '$sorted_querystring_args' variable" do
    nginx_run_server do
      EventMachine.run do
        req = EventMachine::HttpRequest.new("#{nginx_address}/?c=3&=6&a=1&=5&b=2").get
        req.callback do
          expect(req).to be_http_status(200)
          expect(req.response).to be === '{"args": "c=3&=6&a=1&=5&b=2", "sorted_args": "=5&=6&a=1&b=2&c=3"}'
          EventMachine.stop
        end
      end
    end
  end

  it "should support arrays like parameters" do
    nginx_run_server do
      EventMachine.run do
        req = EventMachine::HttpRequest.new("#{nginx_address}/?a=2&c[]=3&=6&a=1&=5&b=2&c[]=1&c[]=2").get
        req.callback do
          expect(req).to be_http_status(200)
          expect(req.response).to be === '{"args": "a=2&c[]=3&=6&a=1&=5&b=2&c[]=1&c[]=2", "sorted_args": "=5&=6&a=1&a=2&b=2&c[]=1&c[]=2&c[]=3"}'
          EventMachine.stop
        end
      end
    end
  end

  it "should filter specified parameters" do
    nginx_run_server({filter_parameter: ["c", "_"]}) do
      EventMachine.run do
        req = EventMachine::HttpRequest.new("#{nginx_address}/?c=3&=6&a=1&=5&b=2&_=12323&c=7").get
        req.callback do
          expect(req).to be_http_status(200)
          expect(req.response).to be === '{"args": "c=3&=6&a=1&=5&b=2&_=12323&c=7", "sorted_args": "=5&=6&a=1&b=2"}'
          EventMachine.stop
        end
      end
    end
  end

  it "should not return error if there isn't a parameter" do
    nginx_run_server do
      EventMachine.run do
        req = EventMachine::HttpRequest.new("#{nginx_address}/").get
        req.callback do
          expect(req).to be_http_status(200)
          expect(req.response).to be === '{"args": "", "sorted_args": ""}'
          EventMachine.stop
        end
      end
    end
  end

  it "should not return error if all parameters where filtered" do
    nginx_run_server({filter_parameter: ["c", "_"]}) do
      EventMachine.run do
        req = EventMachine::HttpRequest.new("#{nginx_address}/?c=3&_=12323&c=7").get
        req.callback do
          expect(req).to be_http_status(200)
          expect(req.response).to be === '{"args": "c=3&_=12323&c=7", "sorted_args": ""}'
          EventMachine.stop
        end
      end
    end
  end

  it "should be possible use the variable as cache_key" do
    nginx_run_server({filter_parameter: ["c", "_"]}) do
      EventMachine.run do
        req = EventMachine::HttpRequest.new("#{nginx_address}/?c=3&=6&a=1&=5&b=2&_=12323&c=7").get
        req.callback do
          expect(req).to be_http_status(200)
          expect(req.response).to be === '{"args": "c=3&=6&a=1&=5&b=2&_=12323&c=7", "sorted_args": "=5&=6&a=1&b=2"}'

          req = EventMachine::HttpRequest.new("#{nginx_address}/?b=2&c=3&=6&=5&_=12323&c=7&a=1").get
          req.callback do
            expect(req).to be_http_status(200)
            expect(req.response).to be === '{"args": "c=3&=6&a=1&=5&b=2&_=12323&c=7", "sorted_args": "=5&=6&a=1&b=2"}'
            EventMachine.stop
          end
        end
      end
    end
  end

  it "should be possible overwrite the filter parameter list by each location" do
    nginx_run_server({filter_parameter: ["c", "_"], filter_parameter2: ["a", "b"]}) do
      EventMachine.run do
        req = EventMachine::HttpRequest.new("#{nginx_address}/?c=3&=6&a=1&=5&b=2&_=12323&c=7").get
        req.callback do
          expect(req).to be_http_status(200)
          expect(req.response).to be === '{"args": "c=3&=6&a=1&=5&b=2&_=12323&c=7", "sorted_args": "=5&=6&a=1&b=2"}'

          req = EventMachine::HttpRequest.new("#{nginx_address}/overwrite?c=3&=6&a=1&=5&b=2&_=12323&c=7").get
          req.callback do
            expect(req).to be_http_status(200)
            expect(req.response).to be === '{"args": "c=3&=6&a=1&=5&b=2&_=12323&c=7", "sorted_args": "=5&=6&_=12323&c=3&c=7"}'
            EventMachine.stop
          end
        end
      end
    end
  end
end
