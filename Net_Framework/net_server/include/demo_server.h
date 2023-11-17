#pragma once

#include "net.h"

enum class CustomMsgTypes : uint32_t
{
    ServerAccept, ServerDeny, ServerPing, MessageAll, ServerMessage,
};

class custom_server : public hnk::net::server_interface<CustomMsgTypes>
{
public:
    custom_server(uint16_t port) : server_interface(port)
    {
    }

protected:
    bool on_client_connected(std::shared_ptr<hnk::net::connection<CustomMsgTypes>> client) override
    {
        hnk::net::message<CustomMsgTypes> msg;
        msg.header.id = CustomMsgTypes::ServerAccept;
        client->send(msg);
        return true;
    }

    void on_client_disconnected(std::shared_ptr<hnk::net::connection<CustomMsgTypes>> client) override
    {
        std::cout << "Removing client [" << client->get_id() << "]\n";
    }

    void on_message(std::shared_ptr<hnk::net::connection<CustomMsgTypes>> client,
                    hnk::net::message<CustomMsgTypes> msg) override
    {
        switch (msg.header.id)
        {
            case CustomMsgTypes::MessageAll:
            {
                std::cout << "[" << client->get_id() << "]: Message All\n";

                hnk::net::message<CustomMsgTypes> msg;
                msg.header.id = CustomMsgTypes::ServerMessage;
                msg << client->get_id();

                message_all_client(msg);
            }
                break;
            case CustomMsgTypes::ServerPing:
            {
                std::cout << "[" << client->get_id() << "]: Message Ping\n";
                /* echo back */
                message_client(client, msg);
            }
                break;
            default:;
        }
    }
};