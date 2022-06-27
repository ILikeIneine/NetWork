#pragma once
#include <memory>
#include <type_traits>
#include <string>
#include <thread>

#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/websocket/stream.hpp>
#include <boost/beast/core/tcp_stream.hpp>

#include "ServiceHandler.hpp"
#include "proto/metadata.pb.h"

// Detection idioms 
template<class T, class = void>
struct is_valid_controller : std::false_type {};

template<class T>
struct is_valid_controller <T, std::void_t<
    decltype(std::declval<T>().SeizeOneSendMessage()),
    decltype(std::declval<T>().AddRecvMessage(std::declval<MessagePtr&>())) >
> : std::true_type {};

template<class T>
constexpr bool is_valid_controller_v = is_valid_controller<T>::value;
/********************************************************************/


namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
using tcp = net::ip::tcp;

class HeartBeatSession : public std::enable_shared_from_this<HeartBeatSession> 
{
    //static_assert(is_valid_controller_v<T>, 
    //    "T does not contain a member function for seizing message");
public:
    explicit  HeartBeatSession(net::io_context& ioc, std::weak_ptr<ServiceHandler> sh);
    ~HeartBeatSession();
    HeartBeatSession(const HeartBeatSession&) = delete;
    void Run(std::string host, std::string port);

    /*** connection establish ***/
    void AsyncConnect();
    void Write() const;
    void AsyncRead();
    /*** reconnection about ***/
    void TryReconnect();
    /*** register flow ***/
    void ProcessRegister();

private:
    /*** callback handler of each async ***/
    void OnHandshake();
    void OnResolve();
    void OnConnect(tcp::resolver::results_type::endpoint_type ep) ;
    void OnHeartBeating();

    /*** back off ***/
    int CurrentSpan();
    void ResetTimer();



    std::weak_ptr<ServiceHandler> sh_;
    std::string host_;
    std::string port_;
    tcp::resolver::results_type hostSolvingResults_;
    tcp::resolver resolver_;
    beast::flat_buffer buffer_;

    std::thread writeThread_;

    struct StepSetter
    {
        void reset()
        {
            std::srand(static_cast<unsigned int>(std::time(nullptr)));
            span_ = 1;
        }
        int current_span()
        {
            // backoff = min(((2 ^ n) + random_number_milliseconds), maximum_backoff)
            const auto exp = std::min(++span_, 16);
            auto this_step = (1 << std::min(exp, 16)) + rand() % 10;
            if (this_step > 64'000)
                this_step = 64'000;
            return this_step;
        }

    private:
        int span_ = 1;    // meantime regarded as attemps' times   
    }ss_;

    // make ws_ dynamically/lazy initializable, otherwise stream won't be recreate
    // cxx17 `std::optional` will of better use cause in this case we only need the resettability
    // here we use `std::unique_ptr` for substitution
    // more details please move to https://github.com/boostorg/beast/issues/2409
    std::unique_ptr<websocket::stream<beast::tcp_stream>> ws_;

};