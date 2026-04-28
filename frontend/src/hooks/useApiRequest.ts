import { useCallback, useState } from 'react'
import { getErrorMessage } from '../services/error'

interface UseApiRequestOptions {
  silent?: boolean
  onError?: (message: string) => void
}

export function useApiRequest() {
  const [loading, setLoading] = useState(false)

  const run = useCallback(async <T>(request: () => Promise<T>, options?: UseApiRequestOptions): Promise<T> => {
    setLoading(true)

    try {
      return await request()
    } catch (error) {
      const message = getErrorMessage(error)
      if (!options?.silent) {
        options?.onError?.(message)
      }
      throw error
    } finally {
      setLoading(false)
    }
  }, [])

  return {
    loading,
    run,
  }
}
