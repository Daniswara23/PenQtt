from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from datetime import datetime

class ReportGenerator:
    def __init__(self, filename):
        self.filename = filename

    def generate(self, broker_ip, username, password, topics, fuzz_count, flood_info, qos_delay_summary):
        c = canvas.Canvas(self.filename, pagesize=A4)
        width, height = A4

        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, height - 50, "Laporan Simulasi Serangan MQTT")
        c.setFont("Helvetica", 12)
        c.drawString(50, height - 80, f"Tanggal: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        c.drawString(50, height - 100, f"Broker IP: {broker_ip}")
        c.drawString(50, height - 120, f"Username: {username or 'N/A'}")
        c.drawString(50, height - 140, f"Password: {password or 'N/A'}")

        c.drawString(50, height - 170, "Topik yang Disadap:")
        y = height - 190
        for t in list(topics)[:10]:
            c.drawString(70, y, f"- {t}")
            y -= 15
            if y < 100:
                c.showPage()
                y = height - 50

        c.drawString(50, y - 20, f"Jumlah Payload Fuzzing Dikirim: {fuzz_count}")
        y -= 40
        c.drawString(50, y, "Info Subscribe Flood:")
        c.drawString(70, y - 15, f"Topik: {flood_info['topic_count']}")
        c.drawString(70, y - 30, f"Pesan per Topik: {flood_info['messages_per_topic']}")
        y -= 50
        c.drawString(50, y, "Ringkasan Delay Maksimum per QoS:")
        y -= 20
        for qos_level, delay in qos_delay_summary.items():
            if delay == -1:
                text = f"QoS {qos_level} : Gagal"
            else:
                text = f"QoS {qos_level} : {delay:.3f} detik"
            c.drawString(70, y, text)
            y -= 15
            if y < 100:
                c.showPage()
                y = height - 50

        c.showPage()
        c.save()
        print(f"[✓] Laporan PDF disimpan sebagai {self.filename}")
