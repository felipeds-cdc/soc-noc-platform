"""
Detection Engine - SOC/NOC Platform
====================================
Motor de detecção e correlação de eventos de segurança.
Implementa regras de detecção para brute force, port scan,
comportamentos anômalos e correlação de eventos.

⚠️ AVISO ÉTICO: Use apenas em ambientes controlados e autorizados.
"""

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger('detector')


@dataclass
class DetectionRule:
    """Regra de detecção."""
    rule_id: str
    name: str
    description: str
    event_type: str
    severity: str
    threshold: int
    time_window: int  # segundos
    mitre_technique_id: str
    mitre_tactic: str


@dataclass
class Alert:
    """Alerta gerado pelo motor de detecção."""
    alert_id: str
    rule_id: str
    rule_name: str
    event_id: str
    severity: str
    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    timestamp: str = ""
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None


# Regras de detecção
DETECTION_RULES = [
    DetectionRule(
        rule_id='RULE_001',
        name='SSH Brute Force',
        description='Detecta múltiplas tentativas falhas de login SSH',
        event_type='auth_failure',
        severity='high',
        threshold=5,
        time_window=300,  # 5 minutos
        mitre_technique_id='T1110',
        mitre_tactic='Credential Access'
    ),
    DetectionRule(
        rule_id='RULE_002',
        name='Port Scan Detected',
        description='Detecta escaneamento de portas',
        event_type='port_scan',
        severity='medium',
        threshold=20,
        time_window=60,  # 1 minuto
        mitre_technique_id='T1046',
        mitre_tactic='Discovery'
    ),
    DetectionRule(
        rule_id='RULE_003',
        name='Honeypot Intrusion',
        description='Detecta interação significativa com honeypot',
        event_type='honeypot_login',
        severity='medium',
        threshold=1,
        time_window=60,
        mitre_technique_id='T1110',
        mitre_tactic='Credential Access'
    ),
    DetectionRule(
        rule_id='RULE_004',
        name='Suspicious Command Execution',
        description='Detecta execução de comandos suspeitos',
        event_type='suspicious_process',
        severity='high',
        threshold=1,
        time_window=60,
        mitre_technique_id='T1059',
        mitre_tactic='Execution'
    ),
    DetectionRule(
        rule_id='RULE_005',
        name='Possible Reverse Shell',
        description='Detecta possível reverse shell',
        event_type='suspicious_connection',
        severity='critical',
        threshold=1,
        time_window=60,
        mitre_technique_id='T1059',
        mitre_tactic='Command and Control'
    ),
    DetectionRule(
        rule_id='RULE_006',
        name='Distributed Brute Force',
        description='Detecta brute force distribuído de múltiplos IPs',
        event_type='auth_failure',
        severity='critical',
        threshold=10,
        time_window=600,  # 10 minutos
        mitre_technique_id='T1110.003',
        mitre_tactic='Credential Access'
    ),
]


class EventCorrelator:
    """Correlaciona eventos para detectar padrões complexos."""
    
    def __init__(self):
        self.events_buffer: Dict[str, List[dict]] = defaultdict(list)
        self.alerts_generated: List[Alert] = []
        self.ip_event_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        
    def add_event(self, event: dict):
        """Adiciona evento ao buffer de correlação."""
        source_ip = event.get('source_ip', 'unknown')
        event_type = event.get('event_type', 'unknown')
        
        # Adiciona ao buffer
        self.events_buffer[source_ip].append(event)
        
        # Atualiza contadores
        self.ip_event_counts[source_ip][event_type] += 1
        
        # Limpa eventos antigos (mais de 1 hora)
        self._cleanup_old_events(source_ip)
        
    def _cleanup_old_events(self, source_ip: str):
        """Remove eventos antigos do buffer."""
        cutoff = datetime.utcnow() - timedelta(hours=1)
        
        if source_ip in self.events_buffer:
            self.events_buffer[source_ip] = [
                event for event in self.events_buffer[source_ip]
                if datetime.fromisoformat(event.get('timestamp', datetime.utcnow().isoformat())) > cutoff
            ]
    
    def evaluate_rules(self) -> List[Alert]:
        """Avalia todas as regras contra eventos atuais."""
        new_alerts = []
        
        for rule in DETECTION_RULES:
            alerts = self._evaluate_rule(rule)
            new_alerts.extend(alerts)
            
        self.alerts_generated.extend(new_alerts)
        return new_alerts
    
    def _evaluate_rule(self, rule: DetectionRule) -> List[Alert]:
        """Avalia uma regra específica."""
        alerts = []
        
        # Agrupa eventos por IP
        for source_ip, events in self.events_buffer.items():
            # Filtra eventos pelo tipo
            matching_events = [
                e for e in events
                if e.get('event_type') == rule.event_type
            ]
            
            # Verifica threshold
            if len(matching_events) >= rule.threshold:
                # Gera alerta
                alert = Alert(
                    alert_id=f"ALERT_{len(self.alerts_generated) + 1}",
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    event_id=matching_events[-1].get('id', 'unknown'),
                    severity=rule.severity,
                    description=f"{rule.name}: {len(matching_events)} eventos detectados de {source_ip}",
                    source_ip=source_ip,
                    timestamp=datetime.utcnow().isoformat(),
                    mitre_technique_id=rule.mitre_technique_id,
                    mitre_tactic=rule.mitre_tactic
                )
                alerts.append(alert)
                
                logger.info(f"🚨 ALERTA: {rule.name} - {source_ip} ({len(matching_events)} eventos)")
        
        return alerts
    
    def detect_distributed_attack(self) -> List[Alert]:
        """Detecta ataques distribuídos (múltiplos IPs)."""
        alerts = []
        
        # Conta IPs únicos por tipo de evento
        event_type_ips: Dict[str, set] = defaultdict(set)
        
        for source_ip, events in self.events_buffer.items():
            for event in events:
                event_type = event.get('event_type')
                if event_type:
                    event_type_ips[event_type].add(source_ip)
        
        # Verifica se há muitos IPs para o mesmo tipo de evento
        for event_type, ips in event_type_ips.items():
            if len(ips) >= 5:  # 5 ou mais IPs diferentes
                alert = Alert(
                    alert_id=f"ALERT_DIST_{len(alerts) + 1}",
                    rule_id='RULE_006',
                    rule_name='Distributed Attack Detected',
                    event_id='correlated',
                    severity='critical',
                    description=f"Ataque distribuído detectado: {len(ips)} IPs para evento {event_type}",
                    timestamp=datetime.utcnow().isoformat(),
                    mitre_technique_id='T1110.003',
                    mitre_tactic='Credential Access'
                )
                alerts.append(alert)
                
        return alerts
    
    def get_ip_risk_score(self, source_ip: str) -> int:
        """Calcula score de risco para um IP (0-100)."""
        if source_ip not in self.ip_event_counts:
            return 0
            
        counts = self.ip_event_counts[source_ip]
        score = 0
        
        # Pesos por tipo de evento
        weights = {
            'auth_failure': 10,
            'port_scan': 5,
            'honeypot_login': 15,
            'suspicious_process': 20,
            'suspicious_connection': 30,
        }
        
        for event_type, count in counts.items():
            weight = weights.get(event_type, 5)
            score += min(count * weight, 50)  # Cap em 50 por tipo
            
        return min(score, 100)
    
    def get_statistics(self) -> dict:
        """Retorna estatísticas do correlator."""
        total_events = sum(len(events) for events in self.events_buffer.values())
        unique_ips = len(self.events_buffer)
        
        return {
            'total_events': total_events,
            'unique_ips': unique_ips,
            'alerts_generated': len(self.alerts_generated),
            'top_event_types': dict(
                sorted(
                    {
                        event_type: sum(
                            counts.get(event_type, 0)
                            for counts in self.ip_event_counts.values()
                        )
                        for event_type in set().union(*[counts.keys() for counts in self.ip_event_counts.values()])
                    }.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10]
            )
        }


# Singleton
event_correlator = EventCorrelator()


def process_event_and_detect(event: dict) -> List[Alert]:
    """Função conveniente para processar evento e detectar ameaças."""
    event_correlator.add_event(event)
    
    # Avalia regras
    alerts = event_correlator.evaluate_rules()
    
    # Detecta ataques distribuídos
    distributed_alerts = event_correlator.detect_distributed_attack()
    alerts.extend(distributed_alerts)
    
    return alerts
