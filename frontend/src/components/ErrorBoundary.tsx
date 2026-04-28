import { Component, type ErrorInfo, type ReactNode } from 'react'

interface Props {
  children: ReactNode
}

interface State {
  hasError: boolean
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = {
    hasError: false,
  }

  static getDerivedStateFromError(): State {
    return { hasError: true }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Erro de renderização capturado:', error, errorInfo)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="card" role="alert" style={{ margin: 20 }}>
          <h3>Falha inesperada na interface</h3>
          <p style={{ marginTop: 8, color: 'var(--text-secondary)' }}>
            Recarregue a página. Se persistir, verifique os dados retornados pela API.
          </p>
        </div>
      )
    }

    return this.props.children
  }
}
