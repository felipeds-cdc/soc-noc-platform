#!/bin/bash

echo "========================================="
echo " SOC/NOC PLATFORM - HEALTH CHECK"
echo "========================================="

BASE_URL="http://localhost:8000"
USERNAME="admin"
PASSWORD="admin123"  # ⚠️ ajuste conforme sua regra (min 6 chars)

echo ""
echo "🔍 1. Verificando containers Docker..."
docker compose ps

echo ""
echo "🔍 2. Verificando logs do backend..."
docker compose logs backend --tail=20

echo ""
echo "🔍 3. Testando conexão HTTP com backend..."
curl -s $BASE_URL/health | jq . || echo "❌ Backend não respondeu"

echo ""
echo "🔐 4. Testando login..."

LOGIN_RESPONSE=$(curl -s -X POST $BASE_URL/api/auth/login \
-H "Content-Type: application/json" \
-d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")

echo "$LOGIN_RESPONSE" | jq .

TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.access_token')

if [ "$TOKEN" == "null" ] || [ -z "$TOKEN" ]; then
    echo "❌ Falha no login (token não obtido)"
    exit 1
else
    echo "✅ Login OK"
fi

echo ""
echo "📡 5. Testando endpoint /events..."

curl -s $BASE_URL/api/events/ \
-H "Authorization: Bearer $TOKEN" | jq . || echo "❌ Falha em events"

echo ""
echo "📊 6. Testando dashboard KPIs..."

curl -s $BASE_URL/api/dashboard/kpis \
-H "Authorization: Bearer $TOKEN" | jq . || echo "❌ Falha KPIs"

echo ""
echo "📈 7. Testando dashboard time-series..."

curl -s $BASE_URL/api/dashboard/time-series \
-H "Authorization: Bearer $TOKEN" | jq . || echo "❌ Falha time-series"

echo ""
echo "🏆 8. Testando dashboard top-items..."

curl -s $BASE_URL/api/dashboard/top-items \
-H "Authorization: Bearer $TOKEN" | jq . || echo "❌ Falha top-items"

echo ""
echo "🗄️ 9. Testando PostgreSQL (users)..."

docker exec -i socplatform-postgres-1 psql -U soc_user -d soc_noc -c "SELECT COUNT(*) FROM users;"

echo ""
echo "📦 10. Testando Elasticsearch..."

docker exec -i socplatform-elasticsearch-1 curl -s http://localhost:9200/_cluster/health | jq .

echo ""
echo "========================================="
echo " ✅ CHECK FINALIZADO"
echo "========================================="
