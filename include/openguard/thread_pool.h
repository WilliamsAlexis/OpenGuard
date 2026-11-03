/**
 * @file thread_pool.h
 * @brief Implementación de un pool de hilos de trabajo concurrente en C++20.
 * @details Distribuye las tareas de análisis y cómputo de hashes entre los núcleos de CPU
 *          disponibles sin sobrecargar el sistema ni generar contención excesiva.
 */

#pragma once

#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <future>
#include <atomic>
#include <memory>
#include <stdexcept>
#include <tuple>

namespace openguard {

/**
 * @class ThreadPool
 * @brief Gestiona un conjunto de hilos reutilizables para ejecución paralela de tareas.
 */
class ThreadPool {
public:
    /**
     * @brief Construye el pool con una cantidad específica de hilos de trabajo.
     * @param numThreads Número de hilos a instanciar (por defecto std::thread::hardware_concurrency()).
     */
    explicit ThreadPool(size_t numThreads = 0);

    /**
     * @brief Destructor que espera la culminación ordenada de las tareas pendientes.
     */
    ~ThreadPool();

    // Deshabilitar copia y movimiento
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    /**
     * @brief Encola una función o tarea invocable para su ejecución en segundo plano.
     * @tparam F Tipo de la función o lambda.
     * @tparam Args Tipos de los argumentos a transferir.
     * @param f Invocable a ejecutar.
     * @param args Argumentos asociados.
     * @return std::future con el valor de retorno de la tarea.
     */
    template <typename F, typename... Args>
    auto enqueue(F&& f, Args&&... args)
        -> std::future<typename std::invoke_result<F, Args...>::type> {
        using ReturnType = typename std::invoke_result<F, Args...>::type;

        auto task = std::make_shared<std::packaged_task<ReturnType()>>(
            [func = std::forward<F>(f), argsTuple = std::make_tuple(std::forward<Args>(args)...)]() mutable {
                return std::apply(std::move(func), std::move(argsTuple));
            }
        );

        std::future<ReturnType> result = task->get_future();
        {
            std::unique_lock<std::mutex> lock(m_queueMutex);
            if (m_stop) {
                throw std::runtime_error("No se pueden encolar tareas en un ThreadPool detenido");
            }
            m_tasks.emplace([task]() { (*task)(); });
        }
        m_cv.notify_one();
        return result;
    }

    /**
     * @brief Obtiene la cantidad de hilos de trabajo activos en el pool.
     * @return Número de hilos trabajadores.
     */
    [[nodiscard]] size_t getThreadCount() const noexcept { return m_workers.size(); }

    /**
     * @brief Detiene la aceptación de nuevas tareas y espera que la cola se vacíe.
     */
    void shutdown();

private:
    std::vector<std::thread> m_workers;
    std::queue<std::function<void()>> m_tasks;
    std::mutex m_queueMutex;
    std::condition_variable m_cv;
    std::atomic<bool> m_stop{false};
};

} // namespace openguard
