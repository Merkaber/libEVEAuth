/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#include "CallBackTimer.h"
#include "../Auth.h"

EVEAuth::CallBackTimer::CallBackTimer() noexcept : execute(false)
{

}

EVEAuth::CallBackTimer::~CallBackTimer() noexcept
{
    if (execute.load(std::memory_order_acquire)) {
        stop();
    }
}

void EVEAuth::CallBackTimer::start(int interval, const std::function<void(void)>& function) noexcept(false)
{
    if (execute.load(std::memory_order_acquire)) {
        stop();
    }

    execute.store(true, std::memory_order_release);
    thread = std::thread([this, interval, function]()
        {
            while (execute.load(std::memory_order_acquire)) {
                std::this_thread::sleep_for(std::chrono::seconds(interval));
                try {
                    function();
                } catch (EVEAuth::AuthException& e) {
                    throw EVEAuth::AuthException{make_err_msg({F_CBT_NAME, e.what()}), e.get_error_code()};
                }
            }
        }
    );
}

void EVEAuth::CallBackTimer::stop() noexcept
{
    execute.store(false, std::memory_order_release);
    if (thread.joinable()) {
        thread.join();
    }
}

bool EVEAuth::CallBackTimer::is_running() const noexcept
{
    return (execute.load(std::memory_order_acquire) && thread.joinable());
}