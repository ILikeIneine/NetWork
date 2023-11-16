#pragma once

#include "net_common.h"
#include "net_connection.h"

namespace hnk::net
{
template <typename T>
class client_interface
{
protected:
  asio::io_context ioc_;

  std::thread thr_context_;

  std::unique_ptr<connection<T>> conn_;

private:
  tsqueue<owned_message<T>> qmsg_in_;

public:
  client_interface()
  {
  }

  virtual ~client_interface()
  {
    disconnect();
  }


  bool connect(const std::string_view host, const uint16_t port)
  {
    try
    {
      asio::ip::tcp::resolver resolver(ioc_);

      asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(host,
          std::to_string(port));

      conn_ = std::make_unique<connection<T>>(connection<T>::owner::client,
          ioc_, asio::ip::tcp::socket(ioc_), qmsg_in_);

      conn_->connect_to_server(endpoints);

      thr_context_ = std::thread([this] { ioc_.run(); });
    }
    catch (std::exception& e)
    {
      std::cerr << "Client Exception: " << e.what() << '\n';
      return false;
    }
    return true;
  }

  void disconnect()
  {
    if (conn_->is_connected())
    {
      conn_->disconnect();
    }

    ioc_.stop();
    if (thr_context_.joinable())
    {
      thr_context_.join();
    }

    conn_.release();
  }

  bool is_connected()
  {
    return conn_ ? conn_->is_connected() : false;
  }

  void send(const message<T>& msg)
  {
    if (is_connected())
    {
      conn_->send(msg);
    }
  }

  tsqueue<owned_message<T>>& incoming_queue()
  {
    return qmsg_in_;
  }
};
}
