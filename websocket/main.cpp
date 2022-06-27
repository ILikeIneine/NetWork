#include <iostream>
//#include <string>
#include "HeartBeatSession.hpp"

//int main()
//{
//    //BENCHMARK_PREPARE;
//
//    std::vector<std::thread> v;
//    std::this_thread::sleep_for(std::chrono::seconds(2));
//    boost::asio::io_context ioc{ 4 };
//    auto sh = std::make_shared<ServiceHandler>();
//    const auto hs = std::make_shared<HeartBeatSession>(ioc, sh);
//    // start read
//    hs->Run("localhost", "8083");
//    // start process and reply
//    sh->Run();
//
//    for(int i = 0; i < 3; ++i)
//    {
//        v.emplace_back([&ioc] {ioc.run(); });
//    }
//    ioc.run();
//
//    // start write
//    google::protobuf::ShutdownProtobufLibrary();
//    //BENCHMARK_END;
//}
