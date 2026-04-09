#!/bin/bash
# SOC/NOC Platform - Setup Script
# Script para facilitar inicialização da plataforma

set -e

echo "================================================"
echo "  SOC/NOC Platform - Security Operations Center"
echo "  ⚠️  AVISO: Uso exclusivo em ambientes laboratoriais"
echo "================================================"
echo ""

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funções
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker não encontrado. Instale Docker primeiro."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        print_error "Docker Compose não encontrado. Instale Docker Compose primeiro."
        exit 1
    fi
    
    print_success "Docker e Docker Compose encontrados"
}

start_platform() {
    print_info "Iniciando plataforma SOC/NOC..."
    
    # Verifica se .env existe
    if [ ! -f .env ]; then
        print_warning ".env não encontrado. Copiando de .env.example..."
        cp .env.example .env
        print_success ".env criado. Edite conforme necessário."
    fi
    
    # Inicia serviços
    if docker compose version &> /dev/null; then
        docker compose up -d
    else
        docker-compose up -d
    fi
    
    print_success "Serviços iniciados!"
    echo ""
    print_info "Verificando status dos serviços..."
    
    if docker compose version &> /dev/null; then
        docker compose ps
    else
        docker-compose ps
    fi
    
    echo ""
    print_success "Plataforma iniciada!"
    echo ""
    echo "================================================"
    echo "  Acesse os serviços:"
    echo "================================================"
    echo "  🌐 Dashboard:     http://localhost:3000"
    echo "  🔌 Backend API:   http://localhost:8000"
    echo "  📚 API Docs:      http://localhost:8000/docs"
    echo "  🎯 Honeypot SSH:  localhost:2222"
    echo "  💾 Redis:         localhost:6379"
    echo "  🗄️  Elasticsearch: http://localhost:9200"
    echo "  🐘 PostgreSQL:    localhost:5432"
    echo ""
    echo "  Credenciais padrão:"
    echo "    Usuário: admin"
    echo "    Senha: admin123"
    echo "================================================"
}

stop_platform() {
    print_info "Parando plataforma SOC/NOC..."
    
    if docker compose version &> /dev/null; then
        docker compose down
    else
        docker-compose down
    fi
    
    print_success "Serviços parados!"
}

show_logs() {
    SERVICE=${1:-""}
    
    if [ -z "$SERVICE" ]; then
        print_info "Mostrando logs de todos os serviços..."
        if docker compose version &> /dev/null; then
            docker compose logs -f
        else
            docker-compose logs -f
        fi
    else
        print_info "Mostrando logs de $SERVICE..."
        if docker compose version &> /dev/null; then
            docker compose logs -f "$SERVICE"
        else
            docker-compose logs -f "$SERVICE"
        fi
    fi
}

show_status() {
    print_info "Status dos serviços:"
    echo ""
    
    if docker compose version &> /dev/null; then
        docker compose ps
    else
        docker-compose ps
    fi
}

run_simulator() {
    print_info "Iniciando simulador de ataques..."
    
    if docker compose version &> /dev/null; then
        docker compose --profile simulation up -d simulator
    else
        docker-compose --profile simulation up -d simulator
    fi
    
    print_success "Simulador iniciado!"
}

# Main
case "${1:-start}" in
    start)
        check_docker
        start_platform
        ;;
    stop)
        stop_platform
        ;;
    restart)
        stop_platform
        sleep 2
        start_platform
        ;;
    logs)
        show_logs "$2"
        ;;
    status)
        show_status
        ;;
    simulator)
        run_simulator
        ;;
    *)
        echo "Uso: $0 {start|stop|restart|logs|status|simulator}"
        echo ""
        echo "Comandos:"
        echo "  start      - Inicia a plataforma"
        echo "  stop       - Para a plataforma"
        echo "  restart    - Reinicia a plataforma"
        echo "  logs       - Mostra logs (opcional: <serviço>)"
        echo "  status     - Mostra status dos serviços"
        echo "  simulator  - Inicia simulador de ataques"
        exit 1
        ;;
esac
