/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#pragma once


#include "../shared.h"
#include <thread>
#include <atomic>
#include <functional>

#define F_CBT_NAME "CallBackTimer: "

namespace EVEAuth {
    class CallBackTimer {
    public:
        CallBackTimer() noexcept;

        ~CallBackTimer() noexcept;

        void start(int interval, const std::function<void(void)>& function) noexcept(false);

        void stop() noexcept;

        bool is_running() const noexcept;

    private:
        std::atomic<bool> execute;
        std::thread thread;
    };
}