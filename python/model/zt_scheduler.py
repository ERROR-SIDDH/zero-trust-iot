"""
zt_scheduler.py — Zero Trust IoT: NS-3 Python Event Scheduling Bridge.

Bridges Python callables to ns-3's C++ Simulator::Schedule via cppyy.
Retains Python object references to prevent garbage collection or deletion
during asynchronous dispatch from C++.
"""

from typing import Callable, Dict
from ns import ns

_INITIALIZED = False
_PY_CALLBACKS: Dict[int, Callable[[], None]] = {}
_ID_COUNTER = 0


def _init_bridge():
    global _INITIALIZED
    if _INITIALIZED:
        return
    ns.cppyy.cppdef("""
    #ifndef ZT_PYTHON_SCHEDULER_H
    #define ZT_PYTHON_SCHEDULER_H
    #include <cstdint>
    #include "ns3/simulator.h"
    #include "ns3/nstime.h"

    namespace zt_bridge {
        typedef void (*DispatcherFn)(uint64_t);
        static DispatcherFn g_dispatcher = nullptr;

        inline void SetDispatcher(DispatcherFn fn) {
            g_dispatcher = fn;
        }

        inline void Trampoline(uint64_t id) {
            if (g_dispatcher) {
                g_dispatcher(id);
            }
        }

        inline void Schedule(ns3::Time delay, uint64_t id) {
            ns3::Simulator::Schedule(delay, Trampoline, id);
        }
    }
    #endif
    """)
    ns.cppyy.gbl.zt_bridge.SetDispatcher(_python_dispatcher)
    _INITIALIZED = True


def _python_dispatcher(cb_id: int) -> None:
    """Invoked from C++ trampoline when ns-3 timer fires."""
    cb = _PY_CALLBACKS.pop(int(cb_id), None)
    if cb is not None:
        cb()


def schedule(delay: "ns.Time", callback: Callable[[], None]) -> None:
    """
    Schedule a Python callback to be invoked at `delay` in ns-3 simulation time.

    Parameters
    ----------
    delay : ns.Time
        Simulation delay (e.g. ns.Seconds(1.0), ns.MilliSeconds(50))
    callback : Callable[[], None]
        Python function/callable to execute.
    """
    global _ID_COUNTER
    _init_bridge()
    _ID_COUNTER += 1
    cb_id = _ID_COUNTER
    _PY_CALLBACKS[cb_id] = callback
    ns.cppyy.gbl.zt_bridge.Schedule(delay, cb_id)


def reset_scheduler() -> None:
    """Clear any pending callbacks."""
    global _PY_CALLBACKS
    _PY_CALLBACKS.clear()
