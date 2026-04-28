import { useGlobalLoading } from '../contexts/LoadingContext'

export default function GlobalLoading() {
  const { globalLoading } = useGlobalLoading()

  if (!globalLoading) {
    return null
  }

  return (
    <div className="global-loading" aria-live="polite" aria-busy="true">
      <div className="spinner" />
    </div>
  )
}
