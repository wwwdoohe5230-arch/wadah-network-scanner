from flask import Flask, render_template, request, jsonify, send_file
from ipaddress import ip_address, ip_network
from datetime import datetime
from pathlib import Path
import socket, io, json

app = Flask(__name__)
BASE = Path(__file__).resolve().parent
REPORTS = BASE / 'reports'
REPORTS.mkdir(exist_ok=True)
# Safe starter: only private/local IP addresses; small, explicit port list.
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 135: 'MS RPC', 139: 'NetBIOS',
    143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
    3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-alt'
}
PRIVATE_NETWORKS = [ip_network('10.0.0.0/8'), ip_network('172.16.0.0/12'), ip_network('192.168.0.0/16'), ip_network('127.0.0.0/8')]

def is_allowed_private_ip(value):
    try:
        ip = ip_address(value.strip())
        return ip.version == 4 and any(ip in net for net in PRIVATE_NETWORKS), str(ip)
    except ValueError:
        return False, ''

def scan_host(host):
    allowed, normalized = is_allowed_private_ip(host)
    if not allowed:
        raise ValueError('لأمان الاستخدام، النسخة الحالية تفحص عنوان IPv4 خاصاً/محلياً فقط مثل 192.168.1.1، وبإذن منك.')
    results = []
    for port, service in COMMON_PORTS.items():
        state = 'مغلق أو لا يستجيب'
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.35)
                if sock.connect_ex((normalized, port)) == 0:
                    state = 'مفتوح'
        except OSError:
            state = 'تعذر الفحص'
        results.append({'port': port, 'service': service, 'state': state})
    opened = [r for r in results if r['state'] == 'مفتوح']
    report = {
        'target': normalized,
        'created_at': datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z'),
        'ports_checked': len(results),
        'open_count': len(opened),
        'results': results,
        'recommendations': make_recommendations(opened)
    }
    return report

def make_recommendations(opened):
    recommendations = []
    open_ports = {r['port'] for r in opened}
    if 23 in open_ports: recommendations.append('أوقف Telnet إن لم تكن تحتاجه، واستخدم SSH بدلاً منه؛ Telnet لا يشفر بيانات الدخول.')
    if 21 in open_ports: recommendations.append('تحقق من الحاجة إلى FTP واستخدم SFTP/FTPS عند نقل الملفات.')
    if 445 in open_ports: recommendations.append('قيّد SMB على الشبكة الداخلية الموثوقة وحدّث النظام والجدار الناري.')
    if 3389 in open_ports: recommendations.append('قيّد RDP على عناوين موثوقة، واستخدم المصادقة متعددة العوامل أو VPN.')
    if 3306 in open_ports or 5432 in open_ports: recommendations.append('لا تعرّض قاعدة البيانات للشبكات غير الموثوقة؛ اسمح بالوصول من خادم التطبيق فقط.')
    if not recommendations: recommendations.append('راجع كل منفذ مفتوح وتأكد أنه مطلوب ومقيّد بجدار ناري. نتيجة المنفذ وحدها لا تثبت وجود ثغرة.')
    return recommendations

@app.get('/')
def index():
    return render_template('index.html')

@app.post('/api/scan')
def api_scan():
    data = request.get_json(silent=True) or {}
    target = str(data.get('target', ''))
    try:
        report = scan_host(target)
        (REPORTS / 'latest.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        return jsonify({'ok': True, 'report': report})
    except ValueError as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 400

@app.get('/api/report.json')
def report_json():
    path = REPORTS / 'latest.json'
    if not path.exists(): return jsonify({'error': 'لا يوجد تقرير بعد'}), 404
    return send_file(path, as_attachment=True, download_name='wadah-scan-report.json')

@app.get('/api/report.pdf')
def report_pdf():
    path = REPORTS / 'latest.json'
    if not path.exists(): return jsonify({'error': 'نفّذ فحصاً أولاً'}), 404
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ImportError:
        return jsonify({'error': 'مكتبة PDF غير مثبتة. نفّذ: pip install reportlab'}), 500
    report = json.loads(path.read_text(encoding='utf-8'))
    buf = io.BytesIO(); c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4; y = height - 55
    # ReportLab default fonts may not render Arabic shaping perfectly; JSON export remains available.
    lines = [
        'WADAH NETWORK SCANNER - Scan Report',
        f"Target: {report['target']}", f"Date: {report['created_at']}",
        f"Ports checked: {report['ports_checked']} | Open: {report['open_count']}", '', 'Port results:'
    ]
    lines += [f"{r['port']:>5}  {r['service']:<14}  {r['state']}" for r in report['results']]
    lines += ['', 'Recommendations:'] + [f'- {x}' for x in report['recommendations']]
    lines += ['', 'Note: Open ports do not by themselves confirm a vulnerability. Scan only systems you own or are authorized to test.']
    for line in lines:
        if y < 50: c.showPage(); y = height - 55
        c.drawString(45, y, line[:110]); y -= 17
    c.save(); buf.seek(0)
    return send_file(buf, mimetype='application/pdf', as_attachment=True, download_name='wadah-scan-report.pdf')

if __name__ == '__main__':
    # Local development only. Use a production WSGI server for deployment.
    app.run(host='127.0.0.1', port=5000, debug=False)
