// Copyright (C) 2001-2003
// William E. Kempf
//
//  Distributed under the Boost Software License, Version 1.0. (See accompanying
//  file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#include <boost/thread/mutex.hpp>
#include <boost/thread/condition.hpp>
#include <boost/thread/thread.hpp>
#include <boost/thread/xtime.hpp>
#include <iostream>

#if defined(BOOST_HAS_WINTHREADS)
#   include <windows.h>
#   include <process.h>
#endif

enum game_state
{
    START,
    PLAYER_A,
    PLAYER_B,
    GAME_OVER,
    ONE_PLAYER_GONE,
    BOTH_PLAYERS_GONE
};

int state;
boost::mutex mutex;
boost::condition cond;

char* player_name(int state)
{
    if (state == PLAYER_A)
        return "PLAYER-A";
    if (state == PLAYER_B)
        return "PLAYER-B";
    throw "bad player";
    return 0;
}

void player(void* param)
{
    boost::mutex::scoped_lock lock(mutex);

    int active = (int)param;
    int other = active == PLAYER_A ? PLAYER_B : PLAYER_A;

    while (state < GAME_OVER)
    {
        std::cout << player_name(active) << ": Play." << std::endl;
        state = other;
        cond.notify_all();
        do
        {
            cond.wait(lock);
            if (state == other)
            {
                std::cout << "---" << player_name(active)
                          << ": Spurious wakeup!" << std::endl;
            }
        } while (state == other);
    }

    ++state;
    std::cout << player_name(active) << ": Gone." << std::endl;
    cond.notify_all();
}

struct thread_adapt
{
    thread_adapt(void (*func)(void*), void* param)
        : _func(func), _param(param)
    {
    }
    int operator()() const
    {
        _func(_param);
        return 0;
    }

    void (*_func)(void*);
    void* _param;
};

class thread_adapter
{
public:
    thread_adapter(void (*func)(void*), void* param)
        : _func(func), _param(param)
    {
    }
    void operator()() const { _func(_param); }
private:
    void (*_func)(void*);
    void* _param;
};

int main(int argc, char* argv[])
{
    state = START;

    boost::thread thrda(thread_adapter(&player, (void*)PLAYER_A));
    boost::thread thrdb(thread_adapter(&player, (void*)PLAYER_B));

    boost::xtime xt;
    boost::xtime_get(&xt, boost::TIME_UTC_);
    xt.sec += 1;
    boost::thread::sleep(xt);
    {
        boost::mutex::scoped_lock lock(mutex);
        std::cout << "---Noise ON..." << std::endl;
    }

    for (int i = 0; i < 1000000000; ++i)
        cond.notify_all();

    {
        boost::mutex::scoped_lock lock(mutex);
        std::cout << "---Noise OFF..." << std::endl;
        state = GAME_OVER;
        cond.notify_all();
        do
        {
            cond.wait(lock);
        } while (state != BOTH_PLAYERS_GONE);
    }

    std::cout << "GAME OVER" << std::endl;

    thrda.join();
    thrdb.join();

    return 0;
}
