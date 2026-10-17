# SOC Home Lab — Wazuh SIEM Detection Lab

Một lab phòng thủ (blue team) tự xây dựng để thực hành triển khai SIEM, mô phỏng tấn công và kiểm chứng khả năng phát hiện (detection) trên cả Linux và Windows.

## Mục tiêu

- Xây dựng một môi trường SOC thu nhỏ bằng VMware Workstation.
- Triển khai Wazuh làm SIEM trung tâm, thu thập log từ nhiều nguồn (SSH, Sysmon).
- Mô phỏng các kịch bản tấn công thực tế (brute-force, thực thi file đáng ngờ) và xác minh pipeline phát hiện hoạt động đúng, từ log nguồn → agent → manager → alert.
- Ghi lại toàn bộ quy trình làm bằng chứng (evidence) phục vụ học tập và làm hồ sơ năng lực cá nhân.

## Kiến trúc Lab

```
                ┌─────────────┐
                │   pfSense   │  (Gateway / Firewall)
                └──────┬──────┘
                       │
        ┌──────────────┼──────────────┬──────────────┐
        │               │              │              │
   ┌─────────┐    ┌───────────┐  ┌───────────┐  ┌───────────┐
   │  Kali   │    │  Windows  │  │  Ubuntu   │  │  (Wazuh   │
   │ (Attacker)│  │  Client   │  │ (Server)  │  │   chạy    │
   │         │    │ + Sysmon  │  │ + Nginx   │  │ trên Ubuntu)│
   └─────────┘    └───────────┘  │ + SSH     │  └───────────┘
                                   │ + Wazuh   │
                                   │  Manager  │
                                   └───────────┘
```

> Ảnh sơ đồ chi tiết: https://github.com/nvnghiagit/SocHOME-LAB/blob/main/evidence/network-diagram.png

### Các máy trong lab

| Máy | Vai trò | Thành phần cài đặt |
|---|---|---|
| pfSense | Gateway / Firewall | Định tuyến, phân mạng LAN |
| Kali Linux | Máy tấn công (Red team) | Nmap, Hydra, Metasploit |
| Windows Client | Máy nạn nhân (endpoint) | Sysmon, Wazuh Agent |
| Ubuntu | Server + SOC | SSH, Wazuh Manager, Wazuh Agent |

## Công cụ & Công nghệ

- **Ảo hóa:** VMware Workstation
- **Firewall/Gateway:** pfSense
- **SIEM:** Wazuh (Manager + Agent + Dashboard)
- **Giám sát Windows:** Sysmon (System Monitor)
- **Công cụ tấn công:** Nmap, Hydra (SSH brute-force)

## Hướng dẫn cài đặt (tóm tắt)

1. Tạo 4 máy ảo trong VMware: pfSense, Windows, Ubuntu, Kali.
2. Cấu hình pfSense làm gateway, các máy còn lại trỏ default gateway về pfSense.
3. Cài đặt Wazuh Manager + Dashboard trên máy Ubuntu.
4. Cài Wazuh Agent trên Windows và trên chính Ubuntu (self-monitoring).
5. Cài Sysmon trên Windows với cấu hình log sự kiện (process creation, network connection, file creation...).
6. Trên Kali, cài sẵn các công cụ pentest cần thiết (Nmap, Hydra đã có sẵn trên Kali mặc định).
7. Xác nhận tất cả agent hiển thị trạng thái **Active** trên Wazuh Dashboard trước khi bắt đầu test.

## Case Study 1 — SSH Brute-force Detection

**Mục tiêu:** Kiểm tra khả năng Wazuh phát hiện tấn công dò mật khẩu SSH (password guessing) nhắm vào Ubuntu.

**Công cụ:** Hydra (chạy từ Kali)

**Các bước thực hiện:**
1. Xác định IP và cổng SSH của Ubuntu bằng Nmap: `nmap -p22 192.168.4.0/24`.
2. Chuẩn bị wordlist mật khẩu (`pass.txt`) trên Kali, có chứa đúng mật khẩu thật của user `nghia` trên Ubuntu để minh họa trường hợp dò trúng.
3. Chạy lệnh tấn công:
   ```bash
   hydra -l nghia -P pass.txt ssh://192.168.4.101 -t 4 -V
   ```
4. Hydra dò thành công mật khẩu sau 4 lần thử.

**Kết quả trên Wazuh:**

| Thời điểm | Rule ID | Mô tả | Level |
|---|---|---|---|
| 14:39:51 | 5557 | unix_chkpwd: Password check failed | 5 |
| 14:39:51 | 5503 | PAM: User login failed | 5 |
| 14:39:51 | 5760 | sshd: authentication failed | 5 |
| 14:39:51 | **5715** | **sshd: authentication success** | 3 |
| 14:39:51 | 5501 | PAM: Login session opened | 3 |
| 14:39:51 | 5502 | PAM: Login session closed | 3 |

- Tổng cộng 7 alert "Authentication failure" được Wazuh ghi nhận trong phiên tấn công.
- Wazuh phân loại kỹ thuật tấn công đúng theo MITRE ATT&CK: **Password Guessing**.
- Chuỗi log cho thấy pipeline hoạt động chính xác: từ các lần thử sai (PAM/sshd) đến lần đăng nhập thành công, rồi mở và đóng phiên SSH.

**Ảnh minh họa:** `evidence/case1-hydra-result.png`, `evidence/case1-wazuh-dashboard.png`, `evidence/case1-wazuh-events.png`

**Nhận xét:** Lab phát hiện chính xác và đầy đủ một cuộc tấn công brute-force SSH thành công, từ giai đoạn dò mật khẩu đến giai đoạn chiếm được phiên đăng nhập — đây là dấu hiệu cảnh báo sớm quan trọng trong thực tế (không chỉ dừng ở việc phát hiện các lần thử sai).

## Case Study 2 — Suspicious File & Process Detection (Sysmon)

**Mục tiêu:** Kiểm tra khả năng Sysmon + Wazuh phát hiện hành vi tạo file đáng ngờ và thực thi lệnh bất thường trên Windows.

**Công cụ:** PowerShell trên Windows Client, file test chuẩn EICAR.

**Các bước thực hiện:**
1. Xác nhận Sysmon đang chạy: `Get-Service sysmon*` → `Running`.
2. Tạo file test EICAR (chuẩn test AV/EDR toàn ngành, hoàn toàn vô hại):
   ```powershell
   $eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
   Set-Content -Path C:\Users\Public\eicar.com.txt -Value $eicar
   ```
3. Thực thi lệnh shell bất thường: `Start-Process cmd.exe -ArgumentList "/c whoami"`.

**Kết quả trên Wazuh:**

| Thời điểm | Rule ID | Mô tả | Level |
|---|---|---|---|
| 15:05:27 | 92217 | Executable dropped in Windows root folder | 6 |
| 15:14:09 | 92032 | Suspicious Windows cmd shell execution | 3 |
| 15:15:26 | **92213** | **Executable file dropped in folder commonly used by malware** | **15** |

**Kết quả trên Windows Defender** (`Get-MpThreatDetection`):
- `ActionSuccess: True`, `ThreatStatusID: 3` (đã xử lý/quarantine)
- Phát hiện lúc 15:10:34, xử lý xong lúc 15:10:49 (~15 giây)
- `ProcessName`: `powershell.exe`, `Resources`: `C:\Users\Public\eicar.com.txt`

**Ảnh minh họa:** `evidence/case2-sysmon-status.png`, `evidence/case2-wazuh-events.png`, `evidence/case2-defender-detection.png`, `evidence/case2-testEICAR.png`

**Nhận xét:** Lab thể hiện khả năng phát hiện đa lớp (defense in depth) — cùng một sự kiện được ghi nhận từ cả góc độ SIEM (Wazuh/Sysmon) lẫn góc độ endpoint AV (Windows Defender), khớp nhau về thời gian và đối tượng, chứng minh pipeline log nhất quán và đáng tin cậy.

## Kết quả tổng thể

- Lab đã kiểm chứng thành công 2 kịch bản phát hiện trên 2 nền tảng khác nhau (Linux qua SSH/PAM, Windows qua Sysmon/Defender).
- Toàn bộ chuỗi log từ nguồn → agent → manager → dashboard hoạt động ổn định, alert sinh ra đúng và kịp thời.
- Wazuh tự động ánh xạ các alert vào kỹ thuật MITRE ATT&CK tương ứng, hỗ trợ việc phân tích theo chuẩn ngành.

## Hướng phát triển tiếp theo

- [ ] Thêm Suricata làm IDS/IPS, tích hợp log vào Wazuh.
- [ ] Thực hiện case study thứ 3: tấn công web (vd. quét lỗ hổng bằng Nikto) nhắm vào Nginx, kiểm tra Wazuh phân tích access/error log.
- [ ] Viết custom rule trong Wazuh (hạ ngưỡng cảnh báo, tạo rule riêng cho pattern cụ thể).
- [ ] Thiết lập cảnh báo tự động qua email/Slack khi có alert mức độ cao (level ≥ 12).
- [ ] Viết playbook phản ứng sự cố (incident response) cho từng case.

## Ghi chú

Lab được xây dựng cho mục đích học tập và thực hành cá nhân trong môi trường cô lập (isolated VMware network). Tất cả các kỹ thuật tấn công (Hydra, EICAR...) đều được thực hiện trong phạm vi lab riêng, không nhắm vào hệ thống của bên thứ ba.
