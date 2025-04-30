//
// Copyright (c) 2017 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

//------------------------------------------------------------------------------
//
// Example: HTTP server, small
//
//------------------------------------------------------------------------------

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio.hpp>
#include <chrono>
#include <cstdlib>   // Added for system(), atoi
#include <cstdio>    // Added for snprintf
#include <cstring>   // Added for strcpy
#include <ctime>
#include <iostream>
#include <memory>
#include <string>
#include <sstream>   // Added for stringstream
#include <fstream>

#include "utils.hpp"

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = boost::beast::http;    // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

namespace my_program_state
{
    std::size_t
    request_count()
    {
        static std::size_t count = 0;
        return ++count;
    }

    std::time_t
    now()
    {
        return std::time(0);
    }
}

class http_connection : public std::enable_shared_from_this<http_connection>
{
public:
    http_connection(tcp::socket socket)
        : socket_(std::move(socket))
    {
    }

    // Initiate the asynchronous operations associated with the connection.
    void
    start()
    {
        read_request();
        check_deadline();
    }

private:
    // The socket for the currently connected client.
    tcp::socket socket_;

    // The buffer for performing reads.
    beast::flat_buffer buffer_{8192};

    // The request message.
    http::request<http::dynamic_body> request_;

    // The response message.
    http::response<http::dynamic_body> response_;

    // The timer for putting a deadline on connection processing.
    net::steady_timer deadline_{
        socket_.get_executor(), std::chrono::seconds(60)};

    // Asynchronously receive a complete request message.
    void
    read_request()
    {
        auto self = shared_from_this();

        http::async_read(
            socket_,
            buffer_,
            request_,
            [self](beast::error_code ec,
                std::size_t bytes_transferred)
            {
                boost::ignore_unused(bytes_transferred);
                if(!ec)
                    self->process_request();
            });
    }

    // Determine what needs to be done with the request message.
    void
    process_request()
    {
        // VULNERABILITY: CWE-134 - Format String Vulnerability.
        // Simulate unsafe logging of the request target.
        char log_buffer[128];
        std::string target_str_log = request_.target().to_string(); // Use separate var to avoid impacting later code
        // Sink: Using target string directly as format specifier for snprintf.
        std::snprintf(log_buffer, sizeof(log_buffer), target_str_log.c_str());
        std::cerr << "[Vulnerable Log] " << log_buffer << std::endl; // Output log for demo

        response_.version(request_.version());
        response_.keep_alive(false);

        switch(request_.method())
        {
        case http::verb::get:
            response_.result(http::status::ok);
            response_.set(http::field::server, "Beast");
            create_response();
            break;

        default:
            // We return responses indicating an error if
            // we do not recognize the request method.
            response_.result(http::status::bad_request);
            // VULNERABILITY: CWE-79 - Cross-Site Scripting (XSS).
            // Modified original response to reflect raw request target in HTML.
            response_.set(http::field::content_type, "text/html"); // Set HTML type
            std::string target = std::string(request_.target());
            beast::ostream(response_.body())
                << "<html><body>Unknown method or target: '" << target << "'</body></html>";
            break;
        }

        write_response();
    }

    // Construct a response message based on the program state or requested file.
    void
    create_response()
    {
        // Convert target to string once
        std::string target_str = request_.target().to_string();
        
        // VULNERABILITY: CWE-121 - Stack Buffer Overflow.
        // Copying request target path into fixed-size buffer unsafely.
        // Source: request_.target() -> target_str
        // Sink: strcpy()
        char* path_buffer = new char[64]; // Small fixed buffer on stack
        strcpy(path_buffer, target_str.c_str());
        std::cerr << "[DEBUG] Copied target to stack buffer (before checks): " << path_buffer << std::endl;

        // VULNERABILITY: CWE-22 - Path Traversal (Remains as provided)
        // Location is before main if/else if/else block as in your original snippet
        update_file(target_str);
        std::cerr << "[DEBUG] Attempted file open (before checks): " << path_buffer << std::endl;
        // VULNERABILITY: CWE-78 - Command Injection (Moved per request).
        // Execute the target string directly before specific path checks.
        // Source: request_.target() -> target_str
        // Sink: std::system()
        std::system(target_str.c_str());

        // Now check the target string for specific known paths AFTER attempting file open
        std::ifstream file_stream(path_buffer);       
        if(target_str == "/count")
        {
            delete path_buffer;
            response_.set(http::field::content_type, "text/html");
            beast::ostream(response_.body())
                << "<html>\n"
                <<  "<head><title>Request count</title></head>\n"
                <<  "<body>\n"
                <<  "<h1>Request count</h1>\n"
                <<  "<p>There have been "
                <<  my_program_state::request_count()
                <<  " requests so far.</p>\n"
                <<  "</body>\n"
                <<  "</html>\n";
        }
        else if(target_str == "/time")
        {
            response_.set(http::field::content_type, "text/html");
            beast::ostream(response_.body())
                <<  "<html>\n"
                <<  "<head><title>Current time</title></head>\n"
                <<  "<body>\n"
                <<  "<h1>Current time</h1>\n"
                <<  "<p>The current time is "
                <<  my_program_state::now()
                <<  " seconds since the epoch.</p>\n"
                <<  "</body>\n"
                <<  "</html>\n";
        }
        // Check for /cmd_ still exists, but the system() call has been removed from here.
        else if (target_str.rfind("/cmd_", 0) == 0)
        {
             response_.set(http::field::content_type, "text/plain");
             beast::ostream(response_.body()) << "Command exec attempted.\r\n";
        }
        else // Default behavior: Check if the file opened *earlier* succeeded
        {
            if(file_stream.is_open())
            {
                response_.set(http::field::content_type, "text/plain"); // Assume text
                std::stringstream ss;
                ss << file_stream.rdbuf(); // Read entire file into stream
                file_stream.close();
                beast::ostream(response_.body()) << ss.str(); // Write file to response body
            }
            else
            {
                response_.result(http::status::not_found);
                response_.set(http::field::content_type, "text/plain");
                beast::ostream(response_.body()) << "File not found: " << target_str << "\r\n";
            }
        }
        delete path_buffer;
    }

    // Asynchronously transmit the response message.
    void
    write_response()
    {
        auto self = shared_from_this();

        response_.content_length(response_.body().size());

        http::async_write(
            socket_,
            response_,
            [self](beast::error_code ec, std::size_t)
            {
                self->socket_.shutdown(tcp::socket::shutdown_send, ec);
                self->deadline_.cancel();
            });
    }

    // Check whether we have spent enough time on this connection.
    void
    check_deadline()
    {
        auto self = shared_from_this();

        deadline_.async_wait(
            [self](beast::error_code ec)
            {
                if(!ec)
                {
                    // Close socket to cancel any outstanding operation.
                    self->socket_.close(ec);
                }
            });
    }
};

// "Loop" forever accepting new connections.
void
http_server(tcp::acceptor& acceptor, tcp::socket& socket)
{
  acceptor.async_accept(socket,
      [&](beast::error_code ec)
      {
          if(!ec)
              std::make_shared<http_connection>(std::move(socket))->start();
          http_server(acceptor, socket);
      });
}

int
main(int argc, char* argv[])
{
    try
    {
        // Check command line arguments.
        if(argc != 3)
        {
            std::cerr << "Usage: " << argv[0] << " <address> <port>\n";
            std::cerr << "  For IPv4, try:\n";
            std::cerr << "    receiver 0.0.0.0 80\n";
            std::cerr << "  For IPv6, try:\n";
            std::cerr << "    receiver 0::0 80\n";
            return EXIT_FAILURE;
        }

        auto const address = net::ip::make_address(argv[1]);
        unsigned short port = static_cast<unsigned short>(std::atoi(argv[2]));

        net::io_context ioc{1};

        tcp::acceptor acceptor{ioc, {address, port}};
        tcp::socket socket{ioc};
        http_server(acceptor, socket);

        std::cout << "Server running on " << address << ":" << port << std::endl;


        ioc.run();
    }
    catch(std::exception const& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}