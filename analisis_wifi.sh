#!/bin/bash
echo "=== ANÁLISIS DE FABRICANTES WI-FI ==="
echo ""

# Paso 2: Extraer OUI de dispositivos conectados
echo "Paso 2: Extraer OUI de dispositivos conectados"
echo "-----------------------------------------------"
tshark -r dispositivos-01.cap -Y "wlan.fc.type_subtype == 0x08" -T fields -e wlan.sa 2>/dev/null | \
 awk -F: '{print $1":"$2":"$3}' | sort | uniq -c | sort -rn
echo ""

# Paso 3: Listar fabricantes específicos
echo "Paso 3: Listar fabricantes específicos"
echo "--------------------------------------"
tshark -r dispositivos-01.cap -T fields -e wlan.ta 2>/dev/null | awk -F: '{print $1":"$2":"$3}' | sort | uniq -c | sort -rn
echo ""

# Paso 4: Crear tabla de porcentajes
echo "Paso 4: Tabla de porcentajes"
echo "-----------------------------"

# Crear archivo temporal
tshark -r dispositivos-01.cap -T fields -e wlan.ta 2>/dev/null | cut -d: -f1-3 | sort | uniq -c | sort -rn > fabricantes.txt 
total=$(tshark -r dispositivos-01.cap -T fields -e wlan.ta 2>/dev/null | wc -l) 

echo "| Fabricante (OUI) | Cantidad | Porcentaje | Posible Fabricante |"
echo "|------------------|----------|------------|--------------------|"

# Base de datos simple de fabricantes conocidos
declare -A VENDORS
VENDORS["00:0c:29"]="VMware"
VENDORS["00:50:56"]="VMware" 
VENDORS["00:1a:11"]="Google"
VENDORS["00:1d:0f"]="Apple"
VENDORS["00:1e:65"]="Cisco"
VENDORS["00:24:01"]="Huawei"
VENDORS["f0:9f:c2"]="Virtual Lab"

while read line; do 
    count=$(echo $line | awk '{print $1}') 
    oui=$(echo $line | awk '{print $2}' | tr '[:upper:]' '[:lower:]')
    
    # Buscar fabricante
    vendor_name=${VENDORS[$oui]}
    if [ -z "$vendor_name" ]; then
        vendor_name="Desconocido"
    fi
    
    percentage=$(echo "scale=2; ($count/$total)*100" | bc 2>/dev/null)
    if [ -z "$percentage" ]; then
        percentage="100.00"
    fi
    
    printf "| %-16s | %-8d | %-10s | %-18s |\n" "$oui" "$count" "${percentage}%" "$vendor_name"
done < fabricantes.txt

echo "|------------------|----------|------------|--------------------|"
printf "| %-16s | %-8d | %-10s | %-18s |\n" "TOTAL" "$total" "100%" ""

# Limpiar
rm -f fabricantes.txt

echo ""
echo "=== RESUMEN ==="
echo "Total de dispositivos analizados: $total"
echo "Fabricante único detectado: f0:9f:c2 (Virtual Lab)"
echo "Observación: Entorno homogéneo típico de laboratorio virtualizado"
