/**
 * @file thread_pool.cpp
 * @brief Implementación de las rutinas de trabajo para el pool de hilos concurrente.
 */

#include "openguard/thread_pool.h"

#include <windows.h>

namespace openguard {

ThreadPool::ThreadPool(size_t numThreads, bool lowPriority) {
    if (numThreads == 0) {
        numThreads = std::thread::hardware_concurrency();
        if (numThreads == 0) numThreads = 4; // Fallback conservador
    }

    m_workers.reserve(numThreads);
    for (size_t i = 0; i < numThreads; ++i) {
        m_workers.emplace_back([this, lowPriority]() {
            if (lowPriority) SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL); // no compite con las aplicaciones del usuario
            while (true) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lock(this->m_queueMutex);
                    this->m_cv.wait(lock, [this]() {
                        return this->m_stop || !this->m_tasks.empty();
                    });

                    if (this->m_stop && this->m_tasks.empty()) {
                        return;
                    }

                    task = std::move(this->m_tasks.front());
                    this->m_tasks.pop();
                }

                // Ejecución segura de la tarea
                try {
                    task();
                } catch (...) {
                    // Evitar que una excepción no controlada termine el hilo de trabajo
                }
            }
        });
    }
}

ThreadPool::~ThreadPool() {
    shutdown();
}

void ThreadPool::shutdown() {
    {
        std::unique_lock<std::mutex> lock(m_queueMutex);
        if (m_stop) return;
        m_stop = true;
    }

    m_cv.notify_all();

    for (std::thread& worker : m_workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    m_workers.clear();
}

} // namespace openguard

