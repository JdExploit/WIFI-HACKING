#!/usr/bin/env python3
"""
Script: deauth_detector.py
Descripción: Detecta y analiza ataques de deautenticación en redes Wi-Fi
Autor: Asistente WiFi Security Lab
Versión: 1.0
"""

import subprocess
import csv
import json
import os
import sys
import time
from datetime import datetime
from collections import defaultdict, Counter
import signal
import threading

class DeauthDetector:
    def __init__(self, interface="wlan0mon", output_dir="./deauth_logs"):
        """
        Inicializa el detector de deauths
        
        Args:
            interface: Interfaz en modo monitor
            output_dir: Directorio para logs
        """
        self.interface = interface
        self.output_dir = output_dir
        self.running = False
        self.stats = {
            "start_time": None,
            "end_time": None,
            "total_deauths": 0,
            "deauths_by_bssid": defaultdict(int),
            "deauths_by_client": defaultdict(int),
            "attack_patterns": [],
            "suspicious_activity": []
        }
        
        # Crear directorio de logs si no existe
        os.makedirs(output_dir, exist_ok=True)
        
    def check_environment(self):
        """Verifica que el entorno esté configurado correctamente"""
        print("[*] Verificando entorno...")
        
        # Verificar permisos de root
        if os.geteuid() != 0:
            print("[-] ERROR: Se necesitan permisos de root")
            print("    Ejecuta: sudo python3 deauth_detector.py")
            return False
        
        # Verificar interfaz
        try:
            result = subprocess.run(
                f"iwconfig {self.interface}",
                shell=True,
                capture_output=True,
                text=True
            )
            if "Mode:Monitor" not in result.stdout:
                print(f"[-] ERROR: {self.interface} no está en modo monitor")
                print("    Ejecuta: sudo airmon-ng start wlan0")
                return False
        except Exception as e:
            print(f"[-] Error verificando interfaz: {e}")
            return False
        
        print("[+] Entorno verificado correctamente")
        return True
    
    def capture_deauths(self, duration=300):
        """
        Captura paquetes de deautenticación
        
        Args:
            duration: Duración de captura en segundos
        """
        print(f"[*] Iniciando captura por {duration} segundos...")
        print(f"[*] Interfaz: {self.interface}")
        print(f"[*] Presiona Ctrl+C para detener antes\n")
        
        # Archivo de captura
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_file = os.path.join(self.output_dir, f"deauth_capture_{timestamp}.pcap")
        csv_file = os.path.join(self.output_dir, f"deauth_analysis_{timestamp}.csv")
        json_file = os.path.join(self.output_dir, f"deauth_report_{timestamp}.json")
        
        # Comando tshark para capturar solo deauth/disassociation
        cmd = (
            f"timeout {duration} tshark -i {self.interface} "
            f"-Y \"wlan.fc.type_subtype == 0x000c || wlan.fc.type_subtype == 0x000a\" "
            f"-T fields "
            f"-e frame.time "
            f"-e wlan.sa "
            f"-e wlan.da "
            f"-e wlan.bssid "
            f"-e wlan.fc.type_subtype "
            f"-e radiotap.dbm_antsignal "
            f"-E separator=, "
            f"-E quote=d "
            f"-E header=y "
            f"> {csv_file} 2>/dev/null"
        )
        
        self.stats["start_time"] = datetime.now().isoformat()
        self.running = True
        
        try:
            # Ejecutar captura
            print("[*] Capturando paquetes de deautenticación...")
            process = subprocess.run(cmd, shell=True)
            
        except KeyboardInterrupt:
            print("\n[*] Captura interrumpida por usuario")
        except Exception as e:
            print(f"[-] Error durante captura: {e}")
        finally:
            self.running = False
            self.stats["end_time"] = datetime.now().isoformat()
        
        # Analizar resultados
        if os.path.exists(csv_file) and os.path.getsize(csv_file) > 0:
            self.analyze_deauths(csv_file)
            self.generate_reports(csv_file, json_file)
        else:
            print("[-] No se capturaron paquetes de deautenticación")
            
        return csv_file
    
    def analyze_deauths(self, csv_file):
        """Analiza los paquetes de deautenticación capturados"""
        print(f"\n[*] Analizando {csv_file}...")
        
        deauths = []
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                deauths.append(row)
        
        if not deauths:
            print("[-] No hay datos para analizar")
            return
        
        self.stats["total_deauths"] = len(deauths)
        
        # Contar por BSSID y cliente
        for deauth in deauths:
            bssid = deauth.get('wlan.bssid', 'Unknown')
            client = deauth.get('wlan.da', 'Unknown')
            
            if bssid and bssid != 'Unknown':
                self.stats["deauths_by_bssid"][bssid] += 1
            
            if client and client != 'Unknown':
                self.stats["deauths_by_client"][client] += 1
        
        # Detectar patrones de ataque
        self._detect_attack_patterns(deauths)
        
        # Mostrar resumen
        print(f"[+] Total deauths capturados: {self.stats['total_deauths']}")
        print(f"[+] APs afectados: {len(self.stats['deauths_by_bssid'])}")
        print(f"[+] Clientes afectados: {len(self.stats['deauths_by_client'])}")
        
    def _detect_attack_patterns(self, deauths):
        """Detecta patrones sospechosos en los deauths"""
        if len(deauths) < 10:
            return
        
        # Agrupar por timestamp (por minuto)
        deauths_by_minute = defaultdict(list)
        for deauth in deauths:
            timestamp = deauth.get('frame.time', '')
            if timestamp:
                # Extraer minuto
                minute = timestamp[:16]  # Formato: "Dec  3, 2025 19:30"
                deauths_by_minute[minute].append(deauth)
        
        # Buscar picos de actividad
        for minute, packets in deauths_by_minute.items():
            if len(packets) > 50:  # Más de 50 deauths por minuto = sospechoso
                self.stats["suspicious_activity"].append({
                    "timestamp": minute,
                    "count": len(packets),
                    "type": "High frequency deauth",
                    "severity": "High"
                })
        
        # Buscar ataques dirigidos
        for bssid, count in self.stats["deauths_by_bssid"].items():
            if count > 100:  # Más de 100 deauths a un mismo AP
                self.stats["attack_patterns"].append({
                    "target": bssid,
                    "count": count,
                    "type": "Targeted AP attack",
                    "severity": "High"
                })
        
        # Buscar broadcast deauths
        broadcast_count = sum(1 for d in deauths if d.get('wlan.da') == 'ff:ff:ff:ff:ff:ff')
        if broadcast_count > 20:
            self.stats["attack_patterns"].append({
                "target": "Broadcast",
                "count": broadcast_count,
                "type": "Broadcast deauth attack",
                "severity": "Medium"
            })
    
    def generate_reports(self, csv_file, json_file):
        """Genera reportes del análisis"""
        print(f"\n[*] Generando reportes...")
        
        # Reporte JSON
        with open(json_file, 'w') as f:
            json.dump(self.stats, f, indent=2)
        print(f"[+] Reporte JSON: {json_file}")
        
        # Reporte CSV detallado
        detailed_csv = csv_file.replace('.csv', '_detailed.csv')
        self._generate_detailed_report(detailed_csv)
        
        # Reporte de resumen
        summary_file = os.path.join(self.output_dir, "deauth_summary.txt")
        self._generate_summary_report(summary_file)
        
        # Mostrar alertas si las hay
        if self.stats["attack_patterns"] or self.stats["suspicious_activity"]:
            print("\n⚠️  ALERTAS DE SEGURIDAD DETECTADAS:")
            for alert in self.stats["attack_patterns"] + self.stats["suspicious_activity"]:
                print(f"   • {alert['type']} - Severidad: {alert['severity']}")
    
    def _generate_detailed_report(self, output_file):
        """Genera reporte CSV detallado"""
        try:
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['BSSID', 'Deauth Count', 'Clients Affected', 'Status'])
                
                for bssid, count in sorted(
                    self.stats["deauths_by_bssid"].items(), 
                    key=lambda x: x[1], 
                    reverse=True
                ):
                    # Contar clientes únicos para este BSSID
                    clients = [
                        client for client, client_count 
                        in self.stats["deauths_by_client"].items() 
                        if client_count > 0
                    ]
                    
                    status = "SUSPICIOUS" if count > 50 else "NORMAL"
                    
                    writer.writerow([bssid, count, len(clients), status])
            
            print(f"[+] Reporte detallado: {output_file}")
        except Exception as e:
            print(f"[-] Error generando reporte detallado: {e}")
    
    def _generate_summary_report(self, output_file):
        """Genera reporte de resumen en texto"""
        with open(output_file, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("       REPORTE DE DETECCIÓN DE DEAUTHS\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Fecha de inicio: {self.stats.get('start_time', 'N/A')}\n")
            f.write(f"Fecha de fin: {self.stats.get('end_time', 'N/A')}\n")
            f.write(f"Interfaz: {self.interface}\n\n")
            
            f.write("📊 ESTADÍSTICAS:\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total deauths: {self.stats['total_deauths']}\n")
            f.write(f"APs afectados: {len(self.stats['deauths_by_bssid'])}\n")
            f.write(f"Clientes afectados: {len(self.stats['deauths_by_client'])}\n\n")
            
            if self.stats['deauths_by_bssid']:
                f.write("🎯 APs MÁS AFECTADOS:\n")
                f.write("-" * 40 + "\n")
                for bssid, count in sorted(
                    self.stats['deauths_by_bssid'].items(), 
                    key=lambda x: x[1], 
                    reverse=True
                )[:10]:  # Top 10
                    f.write(f"{bssid}: {count} deauths\n")
                f.write("\n")
            
            if self.stats['attack_patterns']:
                f.write("⚠️  PATRONES DE ATAQUE DETECTADOS:\n")
                f.write("-" * 40 + "\n")
                for pattern in self.stats['attack_patterns']:
                    f.write(f"• {pattern['type']}\n")
                    f.write(f"  Objetivo: {pattern['target']}\n")
                    f.write(f"  Cantidad: {pattern['count']}\n")
                    f.write(f"  Severidad: {pattern['severity']}\n\n")
            
            f.write("\n" + "=" * 60 + "\n")
            f.write("RECOMENDACIONES:\n")
            f.write("-" * 40 + "\n")
            f.write("1. Habilitar Management Frame Protection (PMF)\n")
            f.write("2. Usar WPA3 en lugar de WPA2\n")
            f.write("3. Monitorear red regularmente\n")
            f.write("4. Implementar sistemas de detección de intrusos\n")
            f.write("5. Aislar dispositivos sospechosos\n")
        
        print(f"[+] Reporte de resumen: {output_file}")
    
    def real_time_monitor(self, alert_threshold=10):
        """
        Monitoreo en tiempo real de deauths
        
        Args:
            alert_threshold: Umbral para alertas (deauths por minuto)
        """
        print(f"[*] Iniciando monitoreo en tiempo real...")
        print(f"[*] Umbral de alerta: {alert_threshold} deauths/minuto")
        print(f"[*] Presiona Ctrl+C para detener\n")
        
        # Archivo para alertas en tiempo real
        alert_file = os.path.join(self.output_dir, "realtime_alerts.txt")
        
        # Comando para monitoreo en tiempo real
        cmd = (
            f"tshark -i {self.interface} "
            f"-Y \"wlan.fc.type_subtype == 0x000c\" "
            f"-T fields "
            f"-e frame.time "
            f"-e wlan.sa "
            f"-e wlan.da "
            f"-e wlan.bssid "
        )
        
        self.running = True
        process = subprocess.Popen(
            cmd, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True
        )
        
        deauth_counter = Counter()
        last_alert_time = time.time()
        
        try:
            while self.running:
                line = process.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                # Parsear línea
                parts = line.strip().split('\t')
                if len(parts) >= 4:
                    timestamp = parts[0]
                    source = parts[1]
                    dest = parts[2]
                    bssid = parts[3]
                    
                    # Incrementar contador
                    current_minute = datetime.now().strftime("%Y-%m-%d %H:%M")
                    deauth_counter[current_minute] += 1
                    
                    # Verificar umbral
                    if deauth_counter[current_minute] >= alert_threshold:
                        if time.time() - last_alert_time > 60:  # Alertar solo una vez por minuto
                            alert_msg = (
                                f"[ALERTA] {current_minute}: "
                                f"{deauth_counter[current_minute]} deauths detectados\n"
                                f"  Último: {timestamp} | BSSID: {bssid}\n"
                            )
                            
                            print(f"\n🚨 {alert_msg}")
                            
                            # Guardar alerta
                            with open(alert_file, 'a') as f:
                                f.write(f"{datetime.now()}: {alert_msg}\n")
                            
                            last_alert_time = time.time()
                    
                    # Mostrar en consola (modo verboso opcional)
                    print(f"[{timestamp}] Deauth: {source} -> {dest} (BSSID: {bssid})", end='\r')
                
        except KeyboardInterrupt:
            print("\n[*] Monitoreo detenido por usuario")
        except Exception as e:
            print(f"[-] Error en monitoreo: {e}")
        finally:
            self.running = False
            process.terminate()
            
            # Mostrar resumen
            print(f"\n📊 Resumen del monitoreo:")
            print(f"   Período monitorizado: {len(deauth_counter)} minutos")
            print(f"   Total deauths: {sum(deauth_counter.values())}")
            print(f"   Archivo de alertas: {alert_file}")
    
    def signal_handler(self, sig, frame):
        """Manejador de señales para Ctrl+C"""
        print("\n[*] Deteniendo detector...")
        self.running = False
        sys.exit(0)


def main():
    """Función principal"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Detector de ataques de deautenticación')
    parser.add_argument('--interface', '-i', default='wlan0mon', help='Interfaz en modo monitor')
    parser.add_argument('--duration', '-d', type=int, default=300, help='Duración de captura en segundos')
    parser.add_argument('--mode', '-m', choices=['capture', 'realtime'], default='capture', 
                       help='Modo de operación')
    parser.add_argument('--threshold', '-t', type=int, default=10, 
                       help='Umbral para alertas en tiempo real (deauths/minuto)')
    parser.add_argument('--output', '-o', default='./deauth_logs', help='Directorio de salida')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("       DETECTOR DE ATAQUES DE DEAUTHENTICACIÓN")
    print("=" * 60)
    
    # Crear detector
    detector = DeauthDetector(
        interface=args.interface,
        output_dir=args.output
    )
    
    # Configurar manejo de Ctrl+C
    signal.signal(signal.SIGINT, detector.signal_handler)
    
    # Verificar entorno
    if not detector.check_environment():
        sys.exit(1)
    
    # Ejecutar modo seleccionado
    if args.mode == 'capture':
        detector.capture_deauths(duration=args.duration)
    elif args.mode == 'realtime':
        detector.real_time_monitor(alert_threshold=args.threshold)
    
    print("\n" + "=" * 60)
    print("[+] Análisis completado")
    print("=" * 60)


if __name__ == "__main__":
    main()
