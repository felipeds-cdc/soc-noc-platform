-- Inicialização do banco de dados PostgreSQL
-- SOC/NOC Platform

-- Extensões
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Tabela de usuários
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'analyst', -- admin, analyst, viewer
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de tenants (multi-tenant)
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de eventos
CREATE TABLE IF NOT EXISTS events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source VARCHAR(50) NOT NULL, -- honeypot, agent, wazuh, etc
    event_type VARCHAR(50) NOT NULL, -- brute_force, port_scan, command_execution, etc
    severity VARCHAR(20) NOT NULL, -- low, medium, high, critical
    source_ip INET,
    destination_ip INET,
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(20),
    username VARCHAR(100),
    password VARCHAR(100),
    command TEXT,
    payload JSONB,
    raw_log TEXT,
    mitre_technique_id VARCHAR(20),
    mitre_tactic VARCHAR(100),
    status VARCHAR(20) DEFAULT 'new', -- new, investigating, resolved, false_positive
    analyst_id UUID REFERENCES users(id),
    resolution_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de alertas
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id UUID REFERENCES events(id),
    rule_id VARCHAR(50) NOT NULL,
    rule_name VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL, -- low, medium, high, critical
    status VARCHAR(20) DEFAULT 'triggered', -- triggered, acknowledged, resolved, suppressed
    description TEXT,
    notified_channels JSONB DEFAULT '[]', -- ['console', 'email', 'webhook', 'slack']
    notified_at TIMESTAMP,
    acknowledged_by UUID REFERENCES users(id),
    acknowledged_at TIMESTAMP,
    resolved_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de sessões do honeypot
CREATE TABLE IF NOT EXISTS honeypot_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id VARCHAR(100) UNIQUE NOT NULL,
    source_ip INET NOT NULL,
    source_port INTEGER,
    username VARCHAR(100),
    password VARCHAR(100),
    login_success BOOLEAN DEFAULT false,
    commands_executed JSONB DEFAULT '[]',
    session_duration INTEGER, -- em segundos
    geo_country VARCHAR(50),
    geo_city VARCHAR(50),
    geo_latitude FLOAT,
    geo_longitude FLOAT,
    asn INTEGER,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP
);

-- Tabela de IOCs (Indicadores de Comprometimento)
CREATE TABLE IF NOT EXISTS iocs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type VARCHAR(20) NOT NULL, -- ip, hash, domain, url, email
    value VARCHAR(500) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    confidence INTEGER, -- 0-100
    source VARCHAR(100),
    description TEXT,
    tags JSONB DEFAULT '[]',
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT true
);

-- Tabela de playbooks
CREATE TABLE IF NOT EXISTS playbooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    trigger_event_type VARCHAR(50),
    trigger_severity VARCHAR(20),
    actions JSONB NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de execuções de playbooks
CREATE TABLE IF NOT EXISTS playbook_executions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    playbook_id UUID REFERENCES playbooks(id),
    event_id UUID REFERENCES events(id),
    status VARCHAR(20) DEFAULT 'pending', -- pending, running, completed, failed
    execution_log JSONB,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);

-- Tabela de configurações do sistema
CREATE TABLE IF NOT EXISTS system_config (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key VARCHAR(100) UNIQUE NOT NULL,
    value JSONB NOT NULL,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Índices para performance
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_status ON events(status);
CREATE INDEX IF NOT EXISTS idx_events_tenant_id ON events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_honeypot_sessions_source_ip ON honeypot_sessions(source_ip);
CREATE INDEX IF NOT EXISTS idx_honeypot_sessions_started_at ON honeypot_sessions(started_at);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);

-- Índice full-text para busca de logs
CREATE INDEX IF NOT EXISTS idx_events_raw_log_gin ON events USING gin (raw_log gin_trgm_ops);

-- Inserir usuário admin padrão (senha deve ser alterada no primeiro acesso)
-- O hash é gerado dinamicamente — execute o script setup_admin.py para criar o admin
-- ou defina a variável de ambiente ADMIN_PASSWORD na inicialização.
-- NOTA: Em produção, NUNCA use credenciais padrão. Gere senhas fortes aleatórias.

-- Inserir tenant padrão
INSERT INTO tenants (name, description) VALUES
('Default', 'Tenant padrão para ambiente laboratorial')
ON CONFLICT DO NOTHING;

-- Inserir configurações padrão
INSERT INTO system_config (key, value, description) VALUES
('anonymize_logs', 'false', 'Se deve anonimizar logs sensíveis'),
('alert_threshold_brute_force', '5', 'Número de tentativas para considerar brute force'),
('alert_threshold_port_scan', '20', 'Número de portas para considerar port scan'),
('mitre_attack_enabled', 'true', 'Se integração com MITRE ATT&CK está habilitada'),
('geoip_enabled', 'true', 'Se enriquecimento GeoIP está habilitado')
ON CONFLICT (key) DO NOTHING;

-- Inserir playbooks padrão
INSERT INTO playbooks (name, description, trigger_event_type, trigger_severity, actions) VALUES
(
    'Bloquear IP por Brute Force',
    'Automaticamente bloqueia IP após detectar brute force SSH',
    'brute_force',
    'high',
    '[
        {"type": "block_ip", "params": {"duration": 3600}},
        {"type": "notify", "params": {"channels": ["console", "slack"]}},
        {"type": "create_ioc", "params": {"type": "ip", "confidence": 80}}
    ]'
),
(
    'Investigar Port Scan',
    'Coleta informações sobre IP que realizou port scan',
    'port_scan',
    'medium',
    '[
        {"type": "enrich_ip", "params": {}},
        {"type": "notify", "params": {"channels": ["console"]}},
        {"type": "create_ioc", "params": {"type": "ip", "confidence": 60}}
    ]'
)
ON CONFLICT DO NOTHING;
