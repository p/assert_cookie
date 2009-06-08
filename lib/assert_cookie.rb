# use three modules to keep indentation in this file
module Indent
  module AssertCookie
    module Assertions
      # Custom assertions for cookies
      #
      #   assert_cookie :pass, 
      #     :value => lambda { |value| UUID.parse(value).valid? }
      #
      #   assert_cookie :yellow, :value => ['sunny', 'days']
      #
      #   assert_cookie :delight, :value => 'yum'
      #
      #   assert_cookie :secret, :path => lambda { |path| path =~ /secret/ }, 
      #     :secure => true   
      def assert_cookie(name, options={}, message="")
        clean_backtrace do
          cookie = cookies[name.to_s]
          
          # this plugin has no rails version attached to it, so the following might be actually wrong
          if cookie.respond_to?(:value)
            value = cookie.value
          elsif cookie.is_a?(String)
            value = cookie
          else
            assert false, "Cookie was something unexpected: #{cookie.inspect}"
          end
          
          msg = build_message(message, "expected cookie named <?> but it was not found.", name)
          assert_not_nil cookie, msg
  
          case 
          when options[:value].respond_to?(:call)
            msg = build_message(message,
                    "expected result of value block to be true but it was false.")
            value.each do |value|
              assert(options[:value].call(value), msg)
            end
          when options[:value].respond_to?(:each)
            options[:value].each do |value|
              msg = build_message(message, 
                      "expected cookie value to include <?> but it was not found.", value)
              assert(value.include?(value), msg)
            end
          else
            msg = build_message(message, "expected cookie value to be <?> but it was <?>.",
                    options[:value], value)
            assert(value.include?(options[:value]), msg)
          end if options.key?(:value)

          assert_call_or_value :path, options, cookie, message
          assert_call_or_value :domain, options, cookie, message
          assert_call_or_value :expires, options, cookie, message
          assert_call_or_value :secure, options, cookie, message
        end
      end
      
      # Tests that a cookie named +name+ does not exist. This is useful
      # because cookies['name'] may be nil or [] in a functional test.
      #
      # assert_no_cookie :chocolate
      def assert_no_cookie(name, message="")
        cookie = cookies[name.to_s]
        
        msg = build_message(message, "no cookie expected but found <?>.", name)
        assert_block(msg) { cookie.nil? or (cookie.kind_of?(Array) and cookie.blank?) or cookie == '' }
      end
      
      def assert_cookie_set(name, message="")
        cookie = cookies[name.to_s]
        
        msg = build_message(message, "expected cookie named <?> but it was not found.", name)
        assert_block(msg) { !(cookie.nil? or (cookie.kind_of?(Array) and cookie.blank?) or cookie == '') }
      end
      
      def clear_cookies
        # or: @integration_session.instance_variable_set("@cookies", {})
        reset!
      end
      
    protected
      def assert_call_or_value(name, options, cookie, message="")
        case
        when options[name].respond_to?(:call)
          msg = build_message(message, 
                  "expected result of <?> block to be true but it was false.", name.to_s)
          assert(options[name].call(cookie.send(name)), msg)
        else
          msg = build_message(message, "expected cookie <?> to be <?> but it was <?>.",
                  name.to_s, options[name], cookie.send(name))
          assert_equal(options[name], cookie.send(name), msg)
        end if options.key?(name)
      end
      
    end
  end
end
