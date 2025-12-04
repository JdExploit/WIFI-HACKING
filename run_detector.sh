#!/bin/bash
# Script para ejecutar el detector de deauths

echo "=========================================="
echo "  EJECUTANDO DETECTOR DE DEAUTHS"
echo "=========================================="

# Verificar permisos
if [ "$EUID" -ne 0 ]; then
    echo "❌ ERROR: Se necesitan permisos de root"
    echo "   Ejecuta: sudo $0"
    exit 1
fi

# Verificar dependencias
echo "[*] Verificando dependencias..."
if ! command -v tshark &> /dev/null; then
    echo "❌ tshark no encontrado"
    echo "   Instala: sudo apt install tshark"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "❌ python3 no encontrado"
    echo "   Instala: sudo apt install python3"
    exit 1
fi

# Crear directorio de logs
LOGS_DIR="./deauth_logs"
mkdir -p "$LOGS_DIR"

# Mostrar opciones
echo ""
echo "Selecciona modo de operación:"
echo "1) Captura por tiempo (5 minutos)"
echo "2) Monitoreo en tiempo real"
echo "3) Captura personalizada"
echo ""
read -p "Opción [1-3]: " MODE

case $MODE in
    1)
        echo "[*] Iniciando captura por 5 minutos..."
        sudo python3 deauth_detector.py --mode capture --duration 300
        ;;
    2)
        echo "[*] Iniciando monitoreo en tiempo real..."
        echo "    Presiona Ctrl+C para detener"
        sudo python3 deauth_detector.py --mode realtime --threshold 10
        ;;
    3)
        read -p "Duración (segundos): " DURATION
        read -p "Umbral de alerta: " THRESHOLD
        sudo python3 deauth_detector.py --mode capture --duration "$DURATION" --threshold "$THRESHOLD"
        ;;
    *)
        echo "Opción no válida"
        exit 1
        ;;
esac

echo ""
echo "📁 Los logs se guardaron en: $LOGS_DIR"
echo "=========================================="
