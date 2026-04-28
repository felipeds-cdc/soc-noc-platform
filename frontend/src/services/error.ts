import axios from 'axios'

export class ApiRequestError extends Error {
  status?: number

  constructor(message: string, status?: number) {
    super(message)
    this.name = 'ApiRequestError'
    this.status = status
  }
}

export function getErrorMessage(error: unknown, fallback = 'Ocorreu um erro inesperado.'): string {
  if (axios.isAxiosError(error)) {
    const status = error.response?.status
    const detail = error.response?.data?.detail

    if (typeof detail === 'string' && detail.trim()) {
      return detail
    }

    if (Array.isArray(detail) && detail.length > 0) {
      return detail
        .map((item) => (typeof item?.msg === 'string' ? item.msg : 'Erro de validação'))
        .join(', ')
    }

    if (status === 401) {
      return 'Sessão inválida ou expirada. Faça login novamente.'
    }

    if (status === 422) {
      return 'Dados inválidos. Verifique os campos e tente novamente.'
    }

    if (status && status >= 500) {
      return 'Erro interno do servidor. Tente novamente em instantes.'
    }

    if (!error.response) {
      return 'Falha de rede. Verifique sua conexão com a API.'
    }
  }

  if (error instanceof ApiRequestError) {
    return error.message
  }

  if (error instanceof Error && error.message) {
    return error.message
  }

  return fallback
}
