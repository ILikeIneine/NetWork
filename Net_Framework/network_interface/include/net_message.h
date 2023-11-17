#pragma once

#include "net_common.h"

namespace hnk::net
{

template <typename T>
struct msg_hdr
{
    T id{};
    size_t size = 0;
};

template <typename T>
struct message
{
    msg_hdr<T> header{};
    std::vector<uint8_t> body;

    auto size() const
    {
        return body.size();
    }

    friend std::ostream& operator<<(std::ostream& os, message& msg)
    {
        return os << "ID: " << static_cast<std::underlying_type<T>>(msg.header.id) << "Size: " << msg.header.size
                  << '\n';
    }

    template <typename DataType>
    friend message& operator<<(message& msg, DataType val)
    {
        static_assert(std::is_standard_layout_v<DataType>, "data is not valid to push into message");

        auto sz = msg.body.size();
        msg.body.resize(sz + sizeof(DataType));
        std::memcpy(msg.body.data() + sz, &val, sizeof(DataType));

        msg.header.size = msg.size();
        return msg;
    }

    template <typename DataType>
    friend message& operator>>(message& msg, DataType data)
    {
        static_assert(std::is_standard_layout_v<DataType>, "data is not valid to pull out from message");

        auto sz = msg.body.size();

        auto data_pos = sz - sizeof(data);
        std::memcpy(msg.body.data() + data_pos, &data, sizeof(data));

        msg.body.resize(data_pos);

        msg.header.size = msg.size();
        return msg;
    }

};


template <typename T>
class connection;

template <typename T>
struct owned_message
{
    std::shared_ptr<connection<T>> remote{nullptr};

    message<T> msg_entity;

    friend std::ostream& operator<<(std::ostream& os, owned_message& own_msg)
    {
        return os << own_msg.msg_entity;
    }
};

}
