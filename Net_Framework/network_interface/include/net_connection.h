#pragma once

#include "net_common.h"
#include "net_tsqueue.h"
#include "net_message.h"
#include "net_server.h"


namespace hnk::net
{

template <typename T>
class connection : public std::enable_shared_from_this<connection<T>>
{
public:
    enum class owner
    {
        server, client
    };

protected:
    asio::ip::tcp::socket socket_;
    asio::io_context& ioc_;

    tsqueue<message<T>> qmsg_out_;
    tsqueue<owned_message<T>>& qmsg_in_;

    message<T> msg_temporary_in_;
    owner owner_type_ = owner::server;
    uint32_t id_ = 0;

    uint64_t handshake_out_ = 0;
    uint64_t handshake_in_ = 0;
    uint64_t handshake_check_ = 0;

    bool valid_handshake_ = false;
    bool connection_established_ = false;

public:
    connection(owner belonger, asio::io_context& ioc, asio::ip::tcp::socket socket, tsqueue<owned_message<T>>& q_in)
            : socket_(std::move(socket)), ioc_(ioc), qmsg_in_(q_in)
    {
        owner_type_ = belonger;

        // server -> client
        if (owner_type_ == owner::server)
        {
            handshake_out_ = static_cast<uint64_t>(std::chrono::system_clock::now().time_since_epoch().count());
            handshake_check_ = scramble(handshake_out_);
        } else
        {
            handshake_out_ = 0;
            handshake_check_ = 0;
        }
    }

    virtual ~connection()
    {
    }

    uint32_t get_id() const
    {
        return id_;
    }

    void connect_to_client(server_interface<T>* server, uint32_t uid = 0)
    {
        if (owner_type_ == owner::server)
        {
            if (socket_.is_open())
            {
                id_ = uid;
                //read_header();

                write_validation();

                read_validation(server);
            }
        }
    }

    void connect_to_server(const asio::ip::tcp::resolver::results_type& endpoints)
    {
        if (owner_type_ == owner::client)
        {
            asio::async_connect(socket_, endpoints, [this](std::error_code ec, asio::ip::tcp::endpoint)
            {
                if (!ec)
                {
                    std::cout << "[CONNECTION] established!\n";
                    //read_header();
                    read_validation();
                } else
                {
                    std::cout << "[CONNECTION] Exception: " << ec.message() << '\n';
                }
            });
        }
    }

    void disconnect()
    {
        if (is_connected())
        {
            asio::post(ioc_, [this] { socket_.close(); });
        }
    }

    bool is_connected() const
    {
        return socket_.is_open();
    }

    void start_listening()
    {
    }

    void send(const message<T>& msg)
    {
        asio::post(ioc_, [this, msg]
        {
            bool is_handling = qmsg_out_.empty();
            qmsg_out_.push_back(msg);
            if (is_handling)
            {
                write_header();
            }
        });
    }

private:
    void write_header()
    {
        asio::async_write(socket_, asio::buffer(&qmsg_out_.front().header, sizeof(msg_hdr<T>)),
                          [this](std::error_code ec, std::size_t length)
                          {
                              if (!ec)
                              {
                                  if (this->qmsg_out_.front().body.size() > 0)
                                  {
                                      this->write_body();
                                  } else
                                  {
                                      this->qmsg_out_.pop_front();
                                      if (!this->qmsg_out_.empty())
                                      {
                                          this->write_header();
                                      }
                                  }
                              } else
                              {
                                  std::cout << "Error Occur!" << std::endl;
                                  std::cout << ec.message() << std::endl;
                                  std::cout << "[" << this->id_ << "] Write Header Failed.\n";
                                  socket_.close();
                              }
                          });
    }

    void write_body()
    {
        asio::async_write(socket_, asio::buffer(qmsg_out_.front().body.data(), qmsg_out_.front().size()),
                          [this](std::error_code ec, std::size_t length)
                          {
                              if (!ec)
                              {
                                  /* write whole message end */
                                  this->qmsg_out_.pop_front();
                                  if (!this->qmsg_out_.empty())
                                  {
                                      write_header();
                                  }
                              } else
                              {
                                  std::cout << "[" << this->id_ << "] Write Body Failed.\n";
                                  socket_.close();
                              }
                          });
    }

    void read_header()
    {
        /* read header's bytes */
        asio::async_read(socket_, asio::buffer(&msg_temporary_in_.header, sizeof(msg_hdr<T>)),
                         [this](std::error_code ec, std::size_t length)
                         {
                             if (!ec)
                             {
                                 if (this->msg_temporary_in_.header.size > 0)
                                 {
                                     this->msg_temporary_in_.body.resize(msg_temporary_in_.header.size);
                                     read_body();
                                 } else
                                 {
                                     add_to_incoming_qmsg();
                                 }
                             } else
                             {
                                 std::cout << "[" << this->id_ << "] Read Header Failed.\n";
                                 socket_.close();
                             }
                         });
    }

    void read_body()
    {
        asio::async_read(socket_, asio::buffer(msg_temporary_in_.body.data(), msg_temporary_in_.header.size),
                         [this](std::error_code ec, std::size_t length)
                         {
                             if (!ec)
                             {
                                 add_to_incoming_qmsg();
                             } else
                             {
                                 std::cout << "[" << this->id_ << "] Read Body Failed.\n";
                                 socket_.close();
                             }
                         });
    }

    uint64_t scramble(uint64_t input)
    {
        uint64_t out = input ^ 0xDEADBEEFC0DECAFE;
        out = (out & 0xF0F0F0F0'F0F0F0F0) >> 4 | (out & 0x0F0F0F0F'0F0F0F0F) << 4;
        return out ^ 0xC0DEFACE12345678;
    }

    void write_validation()
    {
        asio::async_write(socket_, asio::buffer(&handshake_out_, sizeof(uint64_t)),
                          [this](std::error_code ec, std::size_t length)
                          {
                              if (!ec)
                              {
                                  // Validation data sent, clients should sit and wait
                                  // for a response (or a closure)
                                  if (owner_type_ == owner::client)
                                      read_header();
                              } else
                              {
                                  socket_.close();
                              }
                          });
    }

    void read_validation(server_interface<T>* server = nullptr)
    {
        asio::async_read(socket_, asio::buffer(&handshake_in_, sizeof(handshake_in_)),
                         [this, server](std::error_code ec, std::size_t length)
                         {
                             if (!ec)
                             {
                                 if (this->owner_type_ == owner::server)
                                 {
                                     if (this->handshake_in_ == this->handshake_check_)
                                     {
                                         std::cout << "Client Validated" << std::endl;
                                         server->on_client_validate(this->shared_from_this());
                                         this->read_header();
                                     } else
                                     {
                                         std::cout << "Client Disconnected (Fail Validation)" << std::endl;
                                         this->socket_.close();
                                     }
                                 } else
                                 {
                                     handshake_out_ = scramble(handshake_in_);
                                     this->write_validation();
                                 }
                             } else
                             {
                                 std::cout << "Client Disconnected (ReadValidation)" << std::endl;
                                 this->socket_.close();
                             }
                         });
    }

    void add_to_incoming_qmsg()
    {
        if (owner_type_ == owner::client)
        {
            qmsg_in_.push_back({nullptr, msg_temporary_in_});
        } else
        {
            qmsg_in_.push_back({this->shared_from_this(), msg_temporary_in_});
        }

        read_header();
    }
};
}
