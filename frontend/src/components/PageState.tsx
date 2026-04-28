interface MessageProps {
  title: string
  message: string
  action?: {
    label: string
    onClick: () => void
  }
}

export function ErrorState({ title, message, action }: MessageProps) {
  return (
    <div className="card" role="alert">
      <h3>{title}</h3>
      <p style={{ marginTop: 8, color: 'var(--text-secondary)' }}>{message}</p>
      {action ? (
        <button className="btn btn-primary" style={{ marginTop: 16 }} onClick={action.onClick}>
          {action.label}
        </button>
      ) : null}
    </div>
  )
}

export function EmptyState({ title, message, action }: MessageProps) {
  return (
    <div className="card">
      <h3>{title}</h3>
      <p style={{ marginTop: 8, color: 'var(--text-secondary)' }}>{message}</p>
      {action ? (
        <button className="btn btn-secondary" style={{ marginTop: 16 }} onClick={action.onClick}>
          {action.label}
        </button>
      ) : null}
    </div>
  )
}
