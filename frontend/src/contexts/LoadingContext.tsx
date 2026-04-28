import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'

interface LoadingContextValue {
  globalLoading: boolean
  activeRequests: number
}

const LoadingContext = createContext<LoadingContextValue | undefined>(undefined)

export function LoadingProvider({ children }: { children: ReactNode }) {
  const [activeRequests, setActiveRequests] = useState(0)

  useEffect(() => {
    const listener = (event: Event) => {
      const customEvent = event as CustomEvent<{ active?: number }>
      setActiveRequests(Number(customEvent.detail?.active || 0))
    }

    window.addEventListener('api:loading', listener)
    return () => window.removeEventListener('api:loading', listener)
  }, [])

  const value = useMemo(
    () => ({
      globalLoading: activeRequests > 0,
      activeRequests,
    }),
    [activeRequests],
  )

  return <LoadingContext.Provider value={value}>{children}</LoadingContext.Provider>
}

export function useGlobalLoading() {
  const context = useContext(LoadingContext)
  if (!context) {
    throw new Error('useGlobalLoading must be used within LoadingProvider')
  }
  return context
}
