#!/usr/bin/env python3
"""
Script: wifi_security_analyzer.py
Descripción: Analizador automatizado de seguridad Wi-Fi WPA2/WPA3
Autor: Asistente WiFi Security Lab
Versión: 1.0
"""

import subprocess
import json
import csv
import re
from datetime import datetime
import os
import sys
from typing import List, Dict, Tuple, Optional
import matplotlib.pyplot as plt

class WiFiSecurityAnalyzer:
    def __init__(self, interface: str = "wlan0mon"):
        """
        Inicializa el analizador de seguridad Wi-Fi
        
        Args:
            interface: Interfaz en modo monitor
        """
        self.interface = interface
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "interface": interface,
            "networks": [],
            "analysis": {}
        }
        
    def check_root(self) -> bool:
        """Verifica si se ejecuta como root"""
        return os.geteuid() == 0
    
    def run_command(self, cmd: str) -> Tuple[str, str]:
        """
        Ejecuta un comando y retorna stdout y stderr
        
        Args:
            cmd: Comando a ejecutar
            
        Returns:
            Tuple (stdout, stderr)
        """
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return "", "Timeout expired"
        except Exception as e:
            return "", str(e)
    
    def scan_networks(self, duration: int = 60) -> List[Dict]:
        """
        Escanea redes Wi-Fi disponibles
        
        Args:
            duration: Duración del escaneo en segundos
            
        Returns:
            Lista de redes detectadas
        """
        print(f"[*] Escaneando redes durante {duration} segundos...")
        
        # Capturar redes con airodump-ng
        output_file = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        cmd = f"timeout {duration} sudo airodump-ng {self.interface} --output-format csv -w {output_file}"
        stdout, stderr = self.run_command(cmd)
        
        networks = []
        
        # Leer archivo CSV generado
        csv_file = f"{output_file}-01.csv"
        if os.path.exists(csv_file):
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                in_networks_section = False
                
                for row in reader:
                    if len(row) > 0:
                        # Detectar inicio de sección de redes
                        if "BSSID" in row[0] and "ESSID" in row[13]:
                            in_networks_section = True
                            continue
                        
                        # Detectar fin de sección (línea vacía o inicio de stations)
                        if in_networks_section and (len(row[0].strip()) == 0 or "Station" in row[0]):
                            break
                        
                        if in_networks_section and len(row) >= 14:
                            network = {
                                "bssid": row[0].strip(),
                                "essid": row[13].strip() if len(row) > 13 else "(hidden)",
                                "channel": row[3].strip() if len(row) > 3 else "",
                                "encryption": row[5].strip() if len(row) > 5 else "",
                                "cipher": row[6].strip() if len(row) > 6 else "",
                                "auth": row[7].strip() if len(row) > 7 else "",
                                "power": row[8].strip() if len(row) > 8 else "",
                                "beacons": row[9].strip() if len(row) > 9 else "",
                                "data": row[10].strip() if len(row) > 10 else "",
                                "clients": []
                            }
                            networks.append(network)
            
            # Limpiar archivos temporales
            for ext in ['.csv', '.cap', '.kismet.csv', '.kismet.netxml']:
                temp_file = f"{output_file}-01{ext}"
                if os.path.exists(temp_file):
                    os.remove(temp_file)
        
        self.results["networks"] = networks
        print(f"[+] {len(networks)} redes detectadas")
        return networks
    
    def analyze_wpa2_security(self, network: Dict) -> Dict:
        """
        Analiza seguridad WPA2 de una red
        
        Args:
            network: Información de la red
            
        Returns:
            Dict con análisis de seguridad
        """
        analysis = {
            "wpa_version": None,
            "pmf_status": None,
            "cipher_strength": None,
            "vulnerabilities": [],
            "recommendations": []
        }
        
        # Determinar versión WPA
        if "WPA2" in network["encryption"]:
            analysis["wpa_version"] = "WPA2"
        elif "WPA3" in network["encryption"]:
            analysis["wpa_version"] = "WPA3"
        elif "WPA" in network["encryption"]:
            analysis["wpa_version"] = "WPA"
        
        # Analizar cifrado
        if "CCMP" in network["cipher"]:
            analysis["cipher_strength"] = "Fuerte (AES-CCMP)"
        elif "TKIP" in network["cipher"]:
            analysis["cipher_strength"] = "Débil (TKIP - vulnerable)"
            analysis["vulnerabilities"].append("TKIP es vulnerable a ataques")
            analysis["recommendations"].append("Actualizar a AES-CCMP")
        
        # Analizar autenticación
        if "SAE" in network["auth"]:
            analysis["pmf_status"] = "Requerido (WPA3)"
            analysis["cipher_strength"] = "Muy Fuerte"
        elif "PSK" in network["auth"]:
            # Verificar PMF mediante beacon analysis
            pmf_check = self.check_pmf_support(network["bssid"])
            analysis["pmf_status"] = pmf_check
        
        # Verificar vulnerabilidades conocidas
        if analysis["wpa_version"] == "WPA2":
            analysis["vulnerabilities"].append("Potencialmente vulnerable a KRACK")
            analysis["vulnerabilities"].append("Sin forward secrecy (si no es SAE)")
            
        if analysis["wpa_version"] == "WPA3":
            analysis["recommendations"].append("WPA3 proporciona máxima seguridad")
        
        return analysis
    
    def check_pmf_support(self, bssid: str) -> str:
        """
        Verifica soporte de Management Frame Protection (PMF)
        
        Args:
            bssid: Dirección MAC del AP
            
        Returns:
            Estado de PMF
        """
        # Capturar beacon frames del AP específico
        temp_file = f"pmf_check_{bssid.replace(':', '')}"
        cmd = f"sudo airodump-ng {self.interface} --bssid {bssid} --write {temp_file} --output-format pcap --write-interval 1 --output-format csv"
        stdout, stderr = self.run_command(cmd)
        
        # Buscar información de PMF en beacon frames
        cmd = f"tshark -r {temp_file}-01.cap -Y 'wlan.bssid == {bssid.lower()}' -V 2>/dev/null | grep -i 'management frame protection'"
        stdout, _ = self.run_command(cmd)
        
        # Limpiar archivo temporal
        if os.path.exists(f"{temp_file}-01.cap"):
            os.remove(f"{temp_file}-01.cap")
        
        if "required: true" in stdout.lower():
            return "Requerido"
        elif "capable: true" in stdout.lower():
            return "Opcional"
        else:
            return "No soportado"
    
    def capture_handshake(self, bssid: str, channel: str, duration: int = 120) -> bool:
        """
        Captura handshake WPA2/WPA3
        
        Args:
            bssid: Dirección MAC del AP
            channel: Canal de la red
            duration: Duración de captura en segundos
            
        Returns:
            True si se capturó handshake, False en caso contrario
        """
        print(f"[*] Intentando capturar handshake de {bssid}...")
        
        output_file = f"handshake_{bssid.replace(':', '')}"
        cmd = f"timeout {duration} sudo airodump-ng {self.interface} --bssid {bssid} --channel {channel} --write {output_file} --output-format pcap"
        
        # Ejecutar en segundo plano
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Esperar y enviar deauth para forzar handshake
        import time
        time.sleep(10)
        
        deauth_cmd = f"sudo aireplay-ng -0 5 -a {bssid} {self.interface}"
        self.run_command(deauth_cmd)
        
        # Esperar a que termine la captura
        process.wait()
        
        # Verificar si se capturó handshake
        check_cmd = f"aircrack-ng {output_file}-01.cap 2>/dev/null | grep -i 'handshake'"
        stdout, _ = self.run_command(check_cmd)
        
        handshake_captured = "handshake" in stdout.lower()
        
        if handshake_captured:
            print(f"[+] Handshake capturado exitosamente")
            self.results["analysis"]["handshake_file"] = f"{output_file}-01.cap"
        else:
            print(f"[-] No se pudo capturar handshake")
        
        return handshake_captured
    
    def analyze_handshake(self, cap_file: str) -> Dict:
        """
        Analiza archivo de handshake capturado
        
        Args:
            cap_file: Ruta del archivo .cap
            
        Returns:
            Dict con análisis del handshake
        """
        analysis = {
            "valid": False,
            "eapol_count": 0,
            "handshake_type": None,
            "security_assessment": {}
        }
        
        if not os.path.exists(cap_file):
            return analysis
        
        # Contar paquetes EAPOL
        cmd = f"tshark -r {cap_file} -Y 'eapol' 2>/dev/null | wc -l"
        stdout, _ = self.run_command(cmd)
        eapol_count = int(stdout.strip()) if stdout.strip().isdigit() else 0
        analysis["eapol_count"] = eapol_count
        
        # Verificar si es handshake válido
        analysis["valid"] = eapol_count >= 4
        
        # Determinar tipo de handshake
        cmd = f"tshark -r {cap_file} -Y 'wlan.sa' -T fields -e wlan.sa 2>/dev/null | head -1"
        stdout, _ = self.run_command(cmd)
        
        if eapol_count > 0:
            analysis["handshake_type"] = "WPA2" if eapol_count == 4 else "WPA3/SAE"
            
            # Análisis de seguridad
            analysis["security_assessment"] = {
                "forward_secrecy": analysis["handshake_type"] == "WPA3/SAE",
                "offline_protection": analysis["handshake_type"] == "WPA3/SAE",
                "dictionary_resistant": analysis["handshake_type"] == "WPA3/SAE"
            }
        
        return analysis
    
    def generate_report(self, output_format: str = "html"):
        """
        Genera reporte del análisis
        
        Args:
            output_format: Formato del reporte (html, json, txt)
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if output_format == "json":
            filename = f"wifi_analysis_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"[+] Reporte generado: {filename}")
            
        elif output_format == "html":
            filename = f"wifi_analysis_{timestamp}.html"
            self._generate_html_report(filename)
            print(f"[+] Reporte HTML generado: {filename}")
            
        else:  # txt
            filename = f"wifi_analysis_{timestamp}.txt"
            self._generate_text_report(filename)
            print(f"[+] Reporte de texto generado: {filename}")
    
    def _generate_html_report(self, filename: str):
        """Genera reporte HTML"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Análisis de Seguridad Wi-Fi</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                .network {{ border: 1px solid #ddd; padding: 10px; margin: 10px 0; }}
                .secure {{ background-color: #d4edda; }}
                .insecure {{ background-color: #f8d7da; }}
                .warning {{ background-color: #fff3cd; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>📡 Reporte de Análisis de Seguridad Wi-Fi</h1>
            <p><strong>Fecha:</strong> {self.results['timestamp']}</p>
            <p><strong>Interfaz:</strong> {self.results['interface']}</p>
            
            <h2>📊 Resumen</h2>
            <p>Total redes detectadas: {len(self.results['networks'])}</p>
            
            <h2>🌐 Redes Detectadas</h2>
        """
        
        for network in self.results['networks']:
            analysis = self.analyze_wpa2_security(network)
            security_class = "secure" if analysis.get("wpa_version") in ["WPA3", "WPA2"] else "insecure"
            
            html += f"""
            <div class="network {security_class}">
                <h3>📶 {network['essid']}</h3>
                <table>
                    <tr><th>BSSID</th><td>{network['bssid']}</td></tr>
                    <tr><th>Canal</th><td>{network['channel']}</td></tr>
                    <tr><th>Encriptación</th><td>{network['encryption']}</td></tr>
                    <tr><th>Cifrado</th><td>{network['cipher']}</td></tr>
                    <tr><th>Autenticación</th><td>{network['auth']}</td></tr>
                    <tr><th>Versión WPA</th><td>{analysis.get('wpa_version', 'No detectado')}</td></tr>
                    <tr><th>PMF</th><td>{analysis.get('pmf_status', 'No aplica')}</td></tr>
                    <tr><th>Fortaleza de cifrado</th><td>{analysis.get('cipher_strength', 'Desconocido')}</td></tr>
                </table>
            """
            
            if analysis.get("vulnerabilities"):
                html += "<h4>⚠️ Vulnerabilidades:</h4><ul>"
                for vuln in analysis["vulnerabilities"]:
                    html += f"<li>{vuln}</li>"
                html += "</ul>"
            
            if analysis.get("recommendations"):
                html += "<h4>💡 Recomendaciones:</h4><ul>"
                for rec in analysis["recommendations"]:
                    html += f"<li>{rec}</li>"
                html += "</ul>"
            
            html += "</div>"
        
        html += """
            <h2>🔒 Conclusiones</h2>
            <p>Este análisis proporciona una evaluación de la seguridad de las redes Wi-Fi detectadas.</p>
            <p><strong>Recomendaciones generales:</strong></p>
            <ul>
                <li>Usar WPA3 siempre que sea posible</li>
                <li>Habilitar Management Frame Protection (PMF)</li>
                <li>Usar contraseñas fuertes y únicas</li>
                <li>Actualizar firmware de routers regularmente</li>
                <li>Evitar redes abiertas para datos sensibles</li>
            </ul>
            <hr>
            <footer>
                <p>Generado por WiFi Security Analyzer v1.0</p>
            </footer>
        </body>
        </html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _generate_text_report(self, filename: str):
        """Genera reporte de texto"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("         REPORTE DE ANÁLISIS DE SEGURIDAD WI-FI\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Fecha: {self.results['timestamp']}\n")
            f.write(f"Interfaz: {self.results['interface']}\n")
            f.write(f"Total redes detectadas: {len(self.results['networks'])}\n\n")
            
            f.write("=" * 60 + "\n")
            f.write("REDES DETECTADAS:\n")
            f.write("=" * 60 + "\n\n")
            
            for i, network in enumerate(self.results['networks'], 1):
                analysis = self.analyze_wpa2_security(network)
                
                f.write(f"[{i}] {network['essid']}\n")
                f.write(f"    BSSID: {network['bssid']}\n")
                f.write(f"    Canal: {network['channel']}\n")
                f.write(f"    Encriptación: {network['encryption']}\n")
                f.write(f"    Cifrado: {network['cipher']}\n")
                f.write(f"    Autenticación: {network['auth']}\n")
                f.write(f"    Versión WPA: {analysis.get('wpa_version', 'No detectado')}\n")
                f.write(f"    PMF: {analysis.get('pmf_status', 'No aplica')}\n")
                f.write(f"    Fortaleza: {analysis.get('cipher_strength', 'Desconocido')}\n")
                
                if analysis.get("vulnerabilities"):
                    f.write("    ⚠️  Vulnerabilidades:\n")
                    for vuln in analysis["vulnerabilities"]:
                        f.write(f"      - {vuln}\n")
                
                if analysis.get("recommendations"):
                    f.write("    💡 Recomendaciones:\n")
                    for rec in analysis["recommendations"]:
                        f.write(f"      - {rec}\n")
                
                f.write("\n")
            
            f.write("=" * 60 + "\n")
            f.write("CONCLUSIONES Y RECOMENDACIONES:\n")
            f.write("=" * 60 + "\n\n")
            
            f.write("1. Priorizar conexión a redes WPA3\n")
            f.write("2. Habilitar PMF en todas las redes WPA2/WPA3\n")
            f.write("3. Usar AES-CCMP en lugar de TKIP\n")
            f.write("4. Implementar contraseñas fuertes\n")
            f.write("5. Actualizar firmware de dispositivos\n")
            f.write("6. Monitorear redes regularmente\n")
            
            f.write("\n" + "=" * 60 + "\n")
            f.write("Generado por WiFi Security Analyzer v1.0\n")
    
    def run_complete_analysis(self):
        """Ejecuta análisis completo"""
        print("=" * 60)
        print("     ANALIZADOR DE SEGURIDAD WI-FI WPA2/WPA3")
        print("=" * 60)
        
        # Verificar permisos
        if not self.check_root():
            print("[-] ERROR: Este script requiere permisos de root")
            print("    Ejecuta: sudo python3 wifi_security_analyzer.py")
            sys.exit(1)
        
        # Escanear redes
        networks = self.scan_networks(duration=30)
        
        if not networks:
            print("[-] No se detectaron redes Wi-Fi")
            return
        
        # Analizar cada red
        print("\n[*] Analizando seguridad de redes...")
        for network in networks:
            analysis = self.analyze_wpa2_security(network)
            network["security_analysis"] = analysis
            
            # Mostrar resumen en consola
            status = "✅" if analysis.get("wpa_version") in ["WPA3", "WPA2"] else "⚠️"
            print(f"{status} {network['essid']}: {network['encryption']} ({analysis.get('wpa_version', 'N/A')})")
        
        # Capturar handshake de ejemplo (primera red WPA2/WPA3)
        print("\n[*] Intentando capturar handshake de ejemplo...")
        for network in networks:
            if network.get("security_analysis", {}).get("wpa_version") in ["WPA2", "WPA3"]:
                if self.capture_handshake(network["bssid"], network["channel"], duration=60):
                    # Analizar handshake capturado
                    cap_file = f"handshake_{network['bssid'].replace(':', '')}-01.cap"
                    if os.path.exists(cap_file):
                        handshake_analysis = self.analyze_handshake(cap_file)
                        self.results["analysis"]["handshake"] = handshake_analysis
                    break
        
        # Generar reportes
        print("\n[*] Generando reportes...")
        self.generate_report("txt")
        self.generate_report("html")
        
        print("\n" + "=" * 60)
        print("[+] Análisis completado exitosamente")
        print("=" * 60)


# Función principal
def main():
    """Función principal del script"""
    # Configuración
    INTERFACE = "wlan0mon"  # Cambiar según tu interfaz
    
    # Crear analizador
    analyzer = WiFiSecurityAnalyzer(interface=INTERFACE)
    
    # Ejecutar análisis completo
    analyzer.run_complete_analysis()


# Ejecutar si es script principal
if __name__ == "__main__":
    main()
