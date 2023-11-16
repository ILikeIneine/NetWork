#pragma once

#include "net_common.h"
#include "net_connection.h"


namespace hnk::net
{
template <typename T>
class server_interface
{
protected:
  tsqueue<owned_message<T>> qmsg_in_;
  std::deque<std::shared_ptr<connection<T>>> qconns_;

  asio::io_context ioc_;
  std::thread thr_context_;

  asio::ip::tcp::acceptor acceptor_;

  uint32_t ID_counter_ = 10000;

public:
  server_interface(uint16_t port)
    : acceptor_(ioc_, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port))
  {
  }

  virtual ~server_interface()
  {
    stop();
  }


  bool start()
  {
    try
    {
      wait_for_client_connection();
      thr_context_ = std::thread([this] { ioc_.run(); });
    }
    catch (std::exception& e)
    {
      std::cerr << "[SERVER] Exception: " << e.what() << '\n';
      return false;
    }
    std::cout << "[SERVER] Started!\n";
    return true;
  }

  void stop()
  {
    ioc_.stop();

    if (thr_context_.joinable()) thr_context_.join();

    std::cout << "[SERVER] Stopped!\n";
  }

  void wait_for_client_connection()
  {
    acceptor_.async_accept(
        [this](std::error_code ec, asio::ip::tcp::socket socket)
          {
            if (!ec)
            {
              std::cout << "[SERVER] New Connection: " << socket.
                  remote_endpoint() << "\n";
              std::shared_ptr<connection<T>> new_client = std::make_shared<
                connection<
                  T>>(connection<T>::owner::server, ioc_, std::move(socket),
                  qmsg_in_);

              if (on_client_connected(new_client))
              {
                this->qconns_.push_back(new_client);
                this->qconns_.back()->connect_to_client(this, ID_counter_++);
                std::cout << "[" << this->qconns_.back()->get_id() << "] Connection Approved\n";
              }
              else
              {
                std::cout << "[-----] Connection Denied\n";
              }
            }
            else
            {
              std::cout << "[SERVER] New Connection Error: " << ec.message() <<
                  '\n';
            }
            this->wait_for_client_connection();
          });
  }

  void message_client(std::shared_ptr<connection<T>> client,
      const message<T> msg)
  {
    if (client && client->is_connected())
    {
      client->send(msg);
    }
    else
    {
      on_client_disconnected(client);
      client.reset();
      qconns_.erase(std::remove(qconns_.begin(), qconns_.end(), client),
          qconns_.end());
    }
  }

  void message_all_client(const message<T> msg,
      std::shared_ptr<connection<T>> ignore_client = nullptr)
  {
    bool invalid_client_exist = false;

    for (auto& client : qconns_)
    {
      if (client && client->is_connected())
      {
        if (client != ignore_client)
        {
          client->send(msg);
        }
      }
      else
      {
        on_client_disconnected(client);
        client.reset();
        invalid_client_exist = true;
      }
    }

    if (invalid_client_exist)
    {
      qconns_.erase(std::remove(qconns_.begin(), qconns_.end(), nullptr),
          qconns_.end());
    }
  }

  void update(size_t max_messages = -1, bool wait = false)
  {
    if (wait) qmsg_in_.wait();

    size_t message_count = 0;
    while (message_count < max_messages && !qmsg_in_.empty())
    {
      auto msg = qmsg_in_.pop_front();
      on_message(msg.remote, msg.msg_entity);
      message_count++;
    }
  }

protected:
  virtual bool on_client_connected(std::shared_ptr<connection<T>> client)
  {
    return false;
  }

  virtual void on_client_disconnected(std::shared_ptr<connection<T>> client)
  {
  }

  virtual void on_message(std::shared_ptr<connection<T>> client, message<T> msg)
  {
  }

  // for connection inject
public:
  virtual void on_client_validate(std::shared_ptr<connection<T>> client)
  {
  }
};
}
