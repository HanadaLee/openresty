require 'nginx_test_helper'
module NginxConfiguration
  def self.default_configuration
    {
      disable_start_stop_server: false,
      master_process: 'off',
      daemon: 'off',

      filter_parameter: nil,
      filter_parameter2: nil,
    }
  end


  def self.template_configuration
  %(
pid               <%= pid_file %>;
error_log         <%= error_log %> debug;

# Development Mode
master_process    <%= master_process %>;
daemon            <%= daemon %>;

worker_processes  <%= nginx_workers %>;

events {
  worker_connections  1024;
  use                 <%= (RUBY_PLATFORM =~ /darwin/) ? 'kqueue' : 'epoll' %>;
}

http {
  access_log      <%= access_log %>;

  proxy_cache_path <%= File.expand_path(nginx_tests_tmp_dir) %>/cache levels=1:2 keys_zone=zone:10m inactive=10d max_size=100m;

  server {
    listen        <%= nginx_port %>;
    server_name   <%= nginx_host %>;

    <%= write_directive("sorted_querysting_filter_parameter", filter_parameter) %>

    location / {
      proxy_set_header Host "static_files_server";
      proxy_pass http://<%= nginx_host %>:<%= nginx_port %>;

      proxy_cache zone;
      proxy_cache_key "$uri$is_args$sorted_querystring_args";
      proxy_cache_valid 200 1m;
    }
  }

  server {
    listen        <%= nginx_port %>;
    server_name   static_files_server;

    <%= write_directive("sorted_querysting_filter_parameter", filter_parameter) %>

    location /overwrite {
      <%= write_directive("sorted_querysting_filter_parameter", filter_parameter2) %>

      return 200 '{"args": "$args", "sorted_args": "$sorted_querystring_args"}';
    }

    location / {
      return 200 '{"args": "$args", "sorted_args": "$sorted_querystring_args"}';
    }
  }
}
  )
  end
end
