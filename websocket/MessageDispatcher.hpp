#pragma once
#include <google/protobuf/message.h>
#include <type_traits>
#include <functional>
#include <memory>
#include <map>

#include "MyDebug.hpp"

using MessagePtr = std::shared_ptr<::google::protobuf::Message>;

class CallbackBase
{
public:
    virtual ~CallbackBase() = default;

    virtual MessagePtr onMessage(const MessagePtr&) = 0;
};


template<typename MsgTy>
class CallbackImpl : public CallbackBase
{
    static_assert(std::is_base_of<::google::protobuf::Message, MsgTy>::value == true, 
        "_MsgTy must be a protobuf Message");

public:
    using ProtobufMessageCallbackT = std::function<MessagePtr(const std::shared_ptr<MsgTy>& message)>;

    explicit CallbackImpl(const ProtobufMessageCallbackT& callback)
        :callback_(callback)
    {}

    MessagePtr onMessage(const MessagePtr& message) override
    {
        // Message* down_cast to specific Message type
        std::shared_ptr<MsgTy> concret = std::dynamic_pointer_cast<MsgTy>(message);
        assert(concret != nullptr);
        return callback_(concret);
    }

private:
    ProtobufMessageCallbackT callback_;
};


class ProtobufDispatcher
{
public:
    using ProtobufMessageCallback = std::function<MessagePtr(const MessagePtr&)>;

    explicit ProtobufDispatcher(ProtobufMessageCallback defaultCallback)
        :defaultCallback_(std::move(defaultCallback))
    {
    }

    ~ProtobufDispatcher() = default;

    MessagePtr onProtobufMessage(const MessagePtr& message)
    {
        const CallbackMap::const_iterator iter = callbacks_.find(message->GetDescriptor());
        if(iter != callbacks_.cend())
        {
            return iter->second->onMessage(message);
        }
        return defaultCallback_(message);
    }

    template<typename T>
    void registerCallback(const typename CallbackImpl<T>::ProtobufMessageCallbackT& callback)
    {
        std::shared_ptr<CallbackImpl<T>> pd = std::make_shared<CallbackImpl<T>>(callback);
        DEBUG("[info] register descriptor = " << T::descriptor()->full_name())
        callbacks_[T::descriptor()] = pd;
    }
    
private:
    using CallbackMap = std::map<const ::google::protobuf::Descriptor*, std::shared_ptr<CallbackBase> >;

    CallbackMap callbacks_;
    ProtobufMessageCallback defaultCallback_;
};
