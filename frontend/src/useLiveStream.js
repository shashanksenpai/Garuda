import { useEffect, useRef } from 'react'

/**
 * Subscribes to /api/live/stream and invokes onMessage({type, data}) for every
 * pipeline event pushed by the backend (event | detection | incident_update |
 * scenario_started | scenario_finished). Auto-reconnects on drop.
 */
export function useLiveStream(onMessage) {
  const handlerRef = useRef(onMessage)
  handlerRef.current = onMessage

  useEffect(() => {
    let es
    let cancelled = false

    function connect() {
      es = new EventSource('/api/live/stream')
      es.onmessage = (evt) => {
        try {
          const parsed = JSON.parse(evt.data)
          handlerRef.current(parsed)
        } catch {
          // ignore malformed frames
        }
      }
      es.onerror = () => {
        es.close()
        if (!cancelled) setTimeout(connect, 1500)
      }
    }

    connect()
    return () => {
      cancelled = true
      es && es.close()
    }
  }, [])
}
