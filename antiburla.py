import re
import sqlite3
from database import check_permission, DB_NAME

# Lista de palavras-chave e padrões suspeitos (Phishing/Burlas frequentes em Portugal)
SUSPICIOUS_KEYWORDS = [
    "mbway", "mb way", "entidade", "referencia", "urgente", 
    "conta suspensa", "autorize o pagamento", "encomenda retida",
    "alfandega", "cartao bloqueado", "cgd", "santander", "millennium", "novobanco"
]

def analyze_message(user_id: int, sender: str, message_content: str):
    """
    Analisa mensagens em tempo real para detetar potenciais fraudes.
    Se detetar algo suspeito, regista o alerta na tabela fraud_logs.
    """
    # 🛑 1. Validação Zero Trust: O utilizador tem a proteção Anti-Burla ativa?
    if not check_permission(user_id, "antiburla"):
        return {"status": "DISABLED", "detail": "Módulo Anti-Burla desativado para este utilizador."}

    content_lower = message_content.lower()
    is_suspicious = False
    detected_keywords = []

    # 2. Verificação de palavras-chave maliciosas
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in content_lower:
            is_suspicious = True
            detected_keywords.append(kw)

    # 3. Deteção de Links/URLs suspeitos (Expressão Regular)
    urls_found = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', message_content)
    if urls_found:
        is_suspicious = True

    # 4. Se for detetada burla, regista no DB local
    if is_suspicious:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        event_type = "SMS_PHISHING"
        simulated_bank = ", ".join(detected_keywords) if detected_keywords else "Link Suspeito"
        
        cursor.execute('''
            INSERT INTO fraud_logs (user_id, event_type, sender_number, message_content, bank_simulated)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, event_type, sender, message_content, simulated_bank))
        
        conn.commit()
        conn.close()

        print(f"[🚨 ALERTA ANTI-BURLA] Tentativa bloqueada! Remetente: {sender} | Padrões: {simulated_bank}")
        return {
            "status": "ALERT", 
            "detail": f"PERIGO: Mensagem suspeita de fraude detetada! Registo guardado com sucesso."
        }

    return {"status": "CLEAN", "detail": "Mensagem segura."}

# --- TESTE DO MÓDULO ANTI-BURLA ---
if __name__ == "__main__":
    print("\n--- TESTE 1: Mensagem normal e segura ---")
    res1 = analyze_message(user_id=1, sender="+351912345678", message_content="Olá pai, chego a casa às 19h para jantar.")
    print(f"Resultado: {res1}\n")

    print("--- TESTE 2: SMS Falsa da Alfândega / Banco (Phishing) ---")
    res2 = analyze_message(user_id=1, sender="MBWAY_INFO", message_content="URGENTE: A sua conta MBWay foi suspensa. Pagamento de entidade e referencia pendente em http://bit.ly/falso-link")
    print(f"Resultado: {res2}\n")
