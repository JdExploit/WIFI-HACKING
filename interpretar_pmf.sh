#!/bin/bash
echo "=================================================================="
echo "         SCRIPT DE INTERPRETACIÓN DE RESULTADOS PMF"
echo "=================================================================="
echo ""

# Verificar archivo de captura
if [ ! -f "beacons_pmf-01.cap" ]; then
    echo "❌ ERROR: No se encuentra el archivo beacons_pmf-01.cap"
    echo ""
    echo "📋 EJECUTA PRIMERO:"
    echo "   sudo airodump-ng wlan0mon --write beacons_pmf --output-format pcap"
    echo "   (Captura durante 30 segundos, luego Ctrl+C)"
    exit 1
fi

echo "📁 Analizando archivo: beacons_pmf-01.cap"
echo ""

# ==================== ANÁLISIS GENERAL ====================
echo "📊 ANÁLISIS GENERAL DE LA CAPTURA"
echo "=================================="

TOTAL_BEACONS=$(tshark -r beacons_pmf-01.cap -Y "wlan.fc.type_subtype == 0x08" 2>/dev/null | wc -l)
REDES_UNICAS=$(tshark -r beacons_pmf-01.cap -Y "wlan.fc.type_subtype == 0x08" -T fields -e wlan.bssid 2>/dev/null | sort -u | wc -l)

echo "• Beacon frames totales: $TOTAL_BEACONS"
echo "• Redes únicas detectadas: $REDES_UNICAS"
echo ""

# ==================== CLASIFICACIÓN POR TIPO DE SEGURIDAD ====================
echo "🔐 CLASIFICACIÓN POR TIPO DE SEGURIDAD"
echo "======================================="

# Contadores
count_open=0
count_wep=0
count_wpa=0
count_wpa2=0
count_wpa3=0

# Analizar cada red
tshark -r beacons_pmf-01.cap -Y "wlan.fc.type_subtype == 0x08" -T fields -e wlan.bssid 2>/dev/null | sort -u | \
while read bssid; do
    # Obtener información de seguridad
    info=$(tshark -r beacons_pmf-01.cap -Y "wlan.bssid == $bssid && wlan.fc.type_subtype == 0x08" -V 2>/dev/null)
    
    if echo "$info" | grep -q "RSN Information"; then
        # Es WPA2/WPA3
        if echo "$info" | grep -qi "sae\|wpa3\|802.11w.*required"; then
            ((count_wpa3++))
        else
            ((count_wpa2++))
        fi
    elif echo "$info" | grep -q "WPA Information"; then
        ((count_wpa++))
    elif echo "$info" | grep -q "Privacy: AP/STA can support WEP"; then
        ((count_wep++))
    else
        ((count_open++))
    fi
done

echo "| Tipo de Red  | Cantidad | Porcentaje |"
echo "|--------------|----------|------------|"

if [ $REDES_UNICAS -gt 0 ]; then
    echo "| Redes Abiertas | $count_open       | $(echo "scale=1; ($count_open*100)/$REDES_UNICAS" | bc)% |"
    echo "| WEP           | $count_wep       | $(echo "scale=1; ($count_wep*100)/$REDES_UNICAS" | bc)% |"
    echo "| WPA           | $count_wpa       | $(echo "scale=1; ($count_wpa*100)/$REDES_UNICAS" | bc)% |"
    echo "| WPA2          | $count_wpa2      | $(echo "scale=1; ($count_wpa2*100)/$REDES_UNICAS" | bc)% |"
    echo "| WPA3          | $count_wpa3      | $(echo "scale=1; ($count_wpa3*100)/$REDES_UNICAS" | bc)% |"
    echo "|--------------|----------|------------|"
    echo "| TOTAL        | $REDES_UNICAS     | 100%        |"
fi

echo ""

# ==================== ANÁLISIS DETALLADO DE PMF ====================
echo "🛡️  ANÁLISIS DETALLADO DE MANAGEMENT FRAME PROTECTION (PMF)"
echo "============================================================"

echo ""
echo "📋 REDES CON RSN (WPA2/WPA3) Y SU ESTADO PMF:"
echo "---------------------------------------------"

echo "| #  | BSSID             | SSID               | PMF Estado      | Nivel Seguridad |"
echo "|----|-------------------|--------------------|-----------------|-----------------|"

counter=1
tshark -r beacons_pmf-01.cap -Y "wlan.fc.type_subtype == 0x08" 2>/dev/null | \
while read line; do
    if echo "$line" | grep -q "RSN Information"; then
        # Extraer información
        bssid=$(echo "$line" | awk '{print $2}')
        ssid=$(echo "$line" | grep -o "SSID=[^,]*" | cut -d= -f2)
        if [ -z "$ssid" ]; then
            ssid="(hidden)"
        fi
        
        # Determinar estado PMF
        if echo "$line" | grep -qi "management frame protection required: true"; then
            pmf_status="REQUERIDO"
            security_level="ALTO (WPA3)"
        elif echo "$line" | grep -qi "management frame protection capable: true"; then
            pmf_status="OPCIONAL"
            security_level="MEDIO"
        else
            pmf_status="INACTIVO"
            security_level="BAJO"
        fi
        
        printf "| %-2d | %-17s | %-18s | %-15s | %-15s |\n" \
               "$counter" "$bssid" "$ssid" "$pmf_status" "$security_level"
        ((counter++))
    fi
done

if [ $counter -eq 1 ]; then
    echo "|    |                   |                    |                 |                 |"
    echo "✅ No se encontraron redes con RSN (WPA2/WPA3) en la captura."
    echo ""
    echo "🔍 Esto significa que:"
    echo "   • Todas las redes detectadas son abiertas, WEP o WPA1"
    echo "   • PMF no es aplicable (solo para WPA2/WPA3)"
fi

echo ""

# ==================== INTERPRETACIÓN DE RESULTADOS ====================
echo "💡 INTERPRETACIÓN DE RESULTADOS"
echo "================================"

echo ""
echo "🔒 ¿QUÉ ES PMF (Management Frame Protection)?"
echo "   • Protege los frames de management (beacon, auth, deauth, etc.)"
echo "   • Previene ataques de deautenticación y disasociación"
echo "   • Obligatorio en WPA3, opcional en WPA2"
echo ""

echo "📊 NIVELES DE PMF DETECTADOS:"
echo "1. 🔴 PMF INACTIVO:"
echo "   • Red WPA2 sin protección adicional"
echo "   • Vulnerable a ataques de deautenticación"
echo "   • Recomendación: Habilitar PMF si los clientes lo soportan"
echo ""
echo "2. 🟡 PMF OPCIONAL:"
echo "   • WPA2 con 802.11w habilitado"
echo "   • Protección si el cliente la soporta"
echo "   • Buen equilibrio compatibilidad/seguridad"
echo ""
echo "3. 🟢 PMF REQUERIDO:"
echo "   • WPA3 o WPA2 con 802.11w obligatorio"
echo "   • Máxima protección contra ataques"
echo "   • Mejor práctica de seguridad"
echo ""

# ==================== RECOMENDACIONES ====================
echo "🎯 RECOMENDACIONES DE SEGURIDAD"
echo "================================"

echo ""
if [ $count_wpa3 -gt 0 ]; then
    echo "✅ Buenas noticias: Hay redes WPA3 con PMF requerido"
    echo "   • Estas ofrecen la mejor seguridad disponible"
    echo "   • Prioriza conectarte a estas redes"
else
    echo "⚠️  No se detectaron redes WPA3"
    echo "   • Considera actualizar a WPA3 si es posible"
fi

echo ""
if [ $count_open -gt 0 ]; then
    echo "⚠️  Se detectaron redes abiertas: $count_open"
    echo "   • No uses para datos sensibles"
    echo "   • Usa siempre VPN en redes abiertas"
    echo "   • PMF no es aplicable en redes abiertas"
fi

echo ""
if [ $count_wpa2 -gt 0 ]; then
    echo "🔧 Para redes WPA2:"
    echo "   • Verifica si soportan PMF (ieee80211w=1 o 2)"
    echo "   • Actualiza clientes que no soporten PMF"
    echo "   • Considera migrar a WPA3"
fi

echo ""
echo "=================================================================="
echo "                    ANÁLISIS COMPLETADO"
echo "=================================================================="
echo ""
echo "📅 Fecha de análisis: $(date)"
echo "🖥️  Equipo: $(hostname)"
echo ""
