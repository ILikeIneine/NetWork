#include "HeartBeatSession.hpp"

#include <boost/asio/strand.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <utility>

#include "../network_message_handler.h"

HeartBeatSession::HeartBeatSession(net::io_context& ioc, std::weak_ptr<ServiceHandler> sh)
    : sh_{std::move(sh)}, resolver_{ net::make_strand(ioc) }
{
    ws_ = std::make_unique<websocket::stream<beast::tcp_stream>>(net::make_strand(ioc));
    ws_->binary(true);
    ResetTimer();
}

HeartBeatSession::~HeartBeatSession()
{
    if(ws_->is_open())
    {
        ws_->close(websocket::close_code::normal);
    }
    if(writeThread_.joinable())
    {
        writeThread_.join();
    }
}

void HeartBeatSession::Run(std::string host, std::string port)
{
    host_ = std::move(host);
    port_ = std::move(port);
    resolver_.async_resolve(host_, port_,
        [this, self{ shared_from_this() }](beast::error_code ec, tcp::resolver::results_type results)
        ->void
    {
        if (ec)
        {
            //DEBUG("[error]: resolve, " << ec.message())
            LOG_ERROR("resolve: {0}", ec.message());
                return;
        }

        hostSolvingResults_ = std::move(results);
        self->OnResolve();
    });

}


void HeartBeatSession::OnResolve()
{
    beast::get_lowest_layer(*ws_).expires_never();
    AsyncConnect();
}


void HeartBeatSession::TryReconnect()
{
    //DEBUG("[info] session has been disconnected, trying to reconnect...")
    LOG_DEBUG("[info] session has been disconnected, trying to reconnect...");
    if (ws_->is_open())
    {
        ws_->close(websocket::close_code::normal);
    }

    // here to re-emplace websocket stream for another connection
    const auto& executor = ws_->get_executor();
    ws_.reset();
    ws_ = std::make_unique<websocket::stream<beast::tcp_stream>>(executor);
    ws_->binary(true);

    // Exponential backoff to avoid peaking connections
    const auto this_step = CurrentSpan();
    //DEBUG("[info] next trial will start after :" << this_step << "ms ")
    LOG_INFO("[info] next trial will start after: {0}ms", this_step );

    std::this_thread::sleep_for(std::chrono::milliseconds(this_step));

    AsyncConnect();
}

void HeartBeatSession::AsyncConnect() 
{
    beast::get_lowest_layer(*ws_).async_connect(hostSolvingResults_,
        [self{ this->shared_from_this() }](beast::error_code ec, tcp::resolver::results_type::endpoint_type ep)
        ->void
    {
        if (ec)
        {
            //DEBUG("[error]: connect, " << ec.message());
            LOG_ERROR("connect, {0}", ec.message());
            self->TryReconnect();
            return;
        }

        // successfully connected
        self->ResetTimer();
        self->OnConnect(ep);
    });
}


void HeartBeatSession::OnConnect(const tcp::resolver::results_type::endpoint_type ep)
{
    //DEBUG("[info] Session Connection Established...")
    LOG_DEBUG("[info] Session Connection Established...");

    beast::get_lowest_layer(*ws_).expires_never();

    ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
    ws_->set_option(websocket::stream_base::decorator(
        [](websocket::request_type& req)->void
        {
            req.set(http::field::user_agent, std::string(BOOST_BEAST_VERSION_STRING) +
                "async bolean client websocket");
        }));

    const auto host = host_ + ':' + std::to_string(ep.port());

    ws_->async_handshake(host, "/",
        [self{ this->shared_from_this() }](beast::error_code ec)
        ->void
    {
        if (ec)
        {
            //DEBUG("[error]: handshake, " << ec.message())
            LOG_ERROR("[error]: handshake, {0}", ec.message());
            return;
        }
        self->OnHandshake();
    });
}


void HeartBeatSession::OnHandshake()
{
    // todo: operations may add before heartbeating, just do it here
    //DEBUG("[info] Handshake Finished...")
    LOG_DEBUG("[info] Handshake Finished...");
    this->OnHeartBeating();
}

// three steps to complete registe
// 1. construct register message 
// 2. synchronously wait the response from remote
// 3. check register response's verification
void HeartBeatSession::ProcessRegister()
{
    //DEBUG("[info] not registed yet, try to register...");
    LOG_DEBUG("[info] not registed yet, try to register...");
    auto sh = sh_.lock(); // no need checking here, no reason.
    const auto registerMsg = sh->RegistRequest(); 
    if (registerMsg.empty())
        return;
    try
    {
        ws_->write(net::buffer(registerMsg));
        buffer_.consume(buffer_.size());
        //DEBUG("[info] wait for registeration answer...");
        LOG_DEBUG("[info] wait for registeration answer...");
        const size_t rc = ws_->read(buffer_);
        if (rc <= 0)
        {
            //DEBUG("[error] illegal register response");
            LOG_ERROR("[error] illegal register response");
            return;
        }
        //DEBUG("[info] rc = " << rc << "bytes");
        LOG_DEBUG("[info] rc = {0} bytes", rc);
        auto msgStr = beast::buffers_to_string(buffer_.data());

        const auto registerOk =
            sh->CheckRegisterResponse(msgStr);
        if (registerOk == 0)
            //DEBUG("[info] registered successfully!")
            LOG_INFO("[info] registered successfully!");
        else
            //DEBUG("[info] registered failed!")
            LOG_INFO("[info] registered failed!");
    }
    catch (...)
    {
        throw;
    }
}



void HeartBeatSession::OnHeartBeating()
{
    const auto sh = sh_.lock();
    if (!sh)
    {
        //DEBUG("[error] service_handler not prepared")
        LOG_ERROR("[error] service_handler not prepared");
        TryReconnect();
    }
    /*************** Registeration ****************/
    while (!sh->CheckRegisterStatus())
    {
        try
        {
            ProcessRegister();
            //DEBUG("[info] Next Registeration Check Will Start After 10 seconds");
            LOG_INFO("[info] Next Registeration Check Will Start After 10 seconds");
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }
        catch (boost::system::system_error const& se)
        {
            //DEBUG("[error] " << se.code().message());
            LOG_ERROR("[error] {0}" ,se.code().message());
            std::async(std::launch::async, &HeartBeatSession::TryReconnect, shared_from_this());
            return;
        }
        catch (std::exception& e)
        {
            //DEBUG("[error] " << e.what());
            LOG_ERROR("[error] {0}" ,e.what());
            std::async(std::launch::async, &HeartBeatSession::TryReconnect, shared_from_this());
            return;
        }
    }

    DEBUG("[info] already registered, self verifying...");

    /*************** self verify ****************/
    try
    {
        buffer_.consume(buffer_.size());
        auto verifyStr = sh->SelfVerify();
        ws_->write(net::buffer(verifyStr));
    }
    catch (boost::system::system_error const& se)
    {
        //DEBUG("[error] " << se.code().message());
        LOG_ERROR("[error] {0}", se.code().message());
        std::async(std::launch::async, &HeartBeatSession::TryReconnect, shared_from_this());
        return;
    }
    catch (std::exception& e)
    {
        //DEBUG("[error] " << e.what());
        LOG_ERROR("[error] {0}" ,e.what());
        std::async(std::launch::async, &HeartBeatSession::TryReconnect, shared_from_this());
        return;
    }

    //DEBUG("async read on");
    LOG_INFO("async read on");
    AsyncRead();

    if (!writeThread_.joinable())
    {
        writeThread_ = std::thread(&HeartBeatSession::Write, this);
    }
}


void HeartBeatSession::Write() const
{
    const auto sh = sh_.lock();
    if (!sh)
    {
        // log
        return;
    }

    // todo: control the switch
    while (true)
    {
        //DEBUG("[info] wait generate message");
        LOG_DEBUG("[info] wait generate message");
        try
        {
            const auto msgStr = sh->SeizeOneSendMessageAsString();
            ws_->write(net::buffer(msgStr));
        }
        catch (boost::system::system_error const& se)
        {
            //std::cout << se.what();
            LOG_ERROR("[system error]: {0}", se.what());
            break;
        }
        catch (...)
        {
            //DEBUG("exception here");
            LOG_ERROR("exception here");
            break;
        }
    }
    //const auto msgStr = sh->SeizeOneSendMessageAsString();
    //ws_->async_write(net::buffer(msgStr),
    //    [self{ this->shared_from_this() }](beast::error_code ec, std::size_t byteTransferred)
    //    ->void
    //{
    //    if (ec)
    //    {
    //        DEBUG("[error]: write, " << ec.what())
    //            return;     // !WARNING! must return to avoid call async_xxxx twice!
    //    }
    //    self->AsyncWrite();
    //});
}

void HeartBeatSession::AsyncRead()
{
    // todo: parse and verify protobuf message, applying the configuration if ok
    //DEBUG("[info] Async read");
    LOG_DEBUG("[info] Async read");
    buffer_.consume(buffer_.size());
    ws_->async_read(buffer_,
        [this, self{ this->shared_from_this() }](beast::error_code ec, std::size_t byteTransferred)
        ->void
    {
        if (ec)
        {
            //DEBUG("[error]: read, " << ec.message());
            LOG_ERROR("[error]: read, {0}" ,ec.message());
            self->TryReconnect();
            return;   // !WARINING! same reason as above
        }
        //DEBUG("[info] new message in")
        LOG_INFO("[info] new message in");
        const std::string msgIn = beast::buffers_to_string(buffer_.data());
        const auto sh = sh_.lock();
        if (sh)
        {
            sh->AddRecvMessage(msgIn);
        }
        else
        {
            // log servicehandler lost, messages are discarded;
        }
        self->AsyncRead();
    });

}

int HeartBeatSession::CurrentSpan()
{
    return ss_.current_span();
}

void HeartBeatSession::ResetTimer()
{
    ss_.reset();
}
