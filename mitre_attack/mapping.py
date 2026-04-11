"""
MITRE ATT&CK Integration - SOC/NOC Platform
=============================================
Mapeamento automático de técnicas ATT&CK e matriz de detecção.

⚠️ AVISO ÉTICO: Use apenas em ambientes controlados e autorizados.
"""

import json
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict


@dataclass
class MITRETechnique:
    technique_id: str
    name: str
    tactic: str
    description: str
    detection_rules: List[str]
    severity: str


# Base de conhecimento MITRE ATT&CK simplificada
MITRE_ATTACK_DB: Dict[str, MITRETechnique] = {
    'T1110': MITRETechnique(
        technique_id='T1110',
        name='Brute Force',
        tactic='Credential Access',
        description='Técnica de tentativa de acesso por força bruta',
        detection_rules=['failed_login_threshold', 'account_lockout'],
        severity='high'
    ),
    'T1110.001': MITRETechnique(
        technique_id='T1110.001',
        name='Password Guessing',
        tactic='Credential Access',
        description='Tentativas de adivinhação de senha',
        detection_rules=['multiple_failed_logins', 'common_passwords'],
        severity='high'
    ),
    'T1110.003': MITRETechnique(
        technique_id='T1110.003',
        name='Password Spraying',
        tactic='Credential Access',
        description='Testar poucas senhas em muitas contas',
        detection_rules=['distributed_login_attempts', 'common_passwords'],
        severity='high'
    ),
    'T1046': MITRETechnique(
        technique_id='T1046',
        name='Network Service Scanning',
        tactic='Discovery',
        description='Escaneamento de portas e serviços de rede',
        detection_rules=['port_scan_threshold', 'syn_scan_detection'],
        severity='medium'
    ),
    'T1059': MITRETechnique(
        technique_id='T1059',
        name='Command and Scripting Interpreter',
        tactic='Execution',
        description='Execução de comandos via interpretador',
        detection_rules=['suspicious_commands', 'encoded_commands'],
        severity='high'
    ),
    'T1078': MITRETechnique(
        technique_id='T1078',
        name='Valid Accounts',
        tactic='Initial Access',
        description='Uso de credenciais válidas comprometidas',
        detection_rules=['anomalous_login_location', 'impossible_travel'],
        severity='critical'
    ),
    'T1021': MITRETechnique(
        technique_id='T1021',
        name='Remote Services',
        tactic='Lateral Movement',
        description='Movimento lateral via serviços remotos',
        detection_rules=['unusual_rdp_connections', 'unusual_ssh_connections'],
        severity='high'
    ),
    'T1071': MITRETechnique(
        technique_id='T1071',
        name='Application Layer Protocol',
        tactic='Command and Control',
        description='Comunicação C2 via protocolos de aplicação',
        detection_rules=['unusual_http_patterns', 'dns_tunneling'],
        severity='critical'
    ),
    'T1048': MITRETechnique(
        technique_id='T1048',
        name='Exfiltration Over Alternative Protocol',
        tactic='Exfiltration',
        description='Exfiltração de dados via protocolos alternativos',
        detection_rules=['large_outbound_transfers', 'unusual_protocols'],
        severity='critical'
    ),
    'T1566': MITRETechnique(
        technique_id='T1566',
        name='Phishing',
        tactic='Initial Access',
        description='Tentativas de phishing',
        detection_rules=['suspicious_emails', 'malicious_attachments'],
        severity='high'
    ),
}

# Mapeamento de táticas
TACTICS_ORDER = [
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Collection',
    'Command and Control',
    'Exfiltration',
    'Impact'
]


class MITREAttackMapper:
    """Mapeia eventos para técnicas MITRE ATT&CK."""
    
    @classmethod
    def map_event_to_technique(cls, event: dict) -> Optional[MITRETechnique]:
        """Mapeia um evento para técnica MITRE."""
        event_type = event.get('event_type', '').lower()
        
        # Mapeamento automático
        type_to_technique = {
            'brute_force': 'T1110',
            'honeypot_login': 'T1110',
            'port_scan': 'T1046',
            'suspicious_process': 'T1059',
            'suspicious_command': 'T1059',
            'auth_failure': 'T1110',
            'unusual_login': 'T1078',
            'lateral_movement': 'T1021',
            'data_exfiltration': 'T1048',
            'c2_communication': 'T1071',
        }
        
        technique_id = type_to_technique.get(event_type)
        if technique_id:
            return cls.get_technique(technique_id)
        
        return None
    
    @classmethod
    def get_technique(cls, technique_id: str) -> Optional[MITRETechnique]:
        """Obtém técnica por ID."""
        return MITRE_ATTACK_DB.get(technique_id)
    
    @classmethod
    def get_matrix(cls, detected_techniques: List[str] = None) -> dict:
        """Retorna matriz ATT&CK com técnicas detectadas."""
        tactics = {}
        
        for tech_id, technique in MITRE_ATTACK_DB.items():
            if detected_techniques and tech_id not in detected_techniques:
                continue
                
            if technique.tactic not in tactics:
                tactics[technique.tactic] = []
                
            tactics[technique.tactic].append({
                'technique_id': technique.technique_id,
                'name': technique.name,
                'severity': technique.severity,
                'detected': tech_id in (detected_techniques or [])
            })
            
        return {
            'tactics': TACTICS_ORDER,
            'matrix': tactics
        }
    
    @classmethod
    def get_kill_chain_analysis(cls, events: List[dict]) -> dict:
        """Analisa cadeia de ataque baseada nos eventos."""
        techniques_found = []
        
        for event in events:
            technique = cls.map_event_to_technique(event)
            if technique:
                techniques_found.append({
                    'technique': technique,
                    'event': event,
                    'timestamp': event.get('timestamp')
                })
        
        # Ordena por tática
        kill_chain = {}
        for item in techniques_found:
            tactic = item['technique'].tactic
            if tactic not in kill_chain:
                kill_chain[tactic] = []
            kill_chain[tactic].append(item)
            
        return {
            'kill_chain': kill_chain,
            'progression': len(kill_chain),
            'severity': 'critical' if len(kill_chain) >= 4 else ('high' if len(kill_chain) >= 2 else 'medium')
        }


# Para uso direto
if __name__ == '__main__':
    # Exemplo de uso
    mapper = MITREAttackMapper()
    
    # Evento de exemplo
    event = {
        'event_type': 'brute_force',
        'source_ip': '10.0.0.1',
        'timestamp': '2026-04-07T10:00:00'
    }
    
    technique = mapper.map_event_to_technique(event)
    if technique:
        print(f"Técnica detectada: {technique.technique_id} - {technique.name}")
        print(f"Tática: {technique.tactic}")
        print(f"Severidade: {technique.severity}")
