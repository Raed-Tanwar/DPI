import subprocess
import os

def run_cmd(cmd):
    res = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    return res.returncode, res.stdout, res.stderr

print("--- CHECK 1: DPIEngine with RULES ---")
code, stdout, stderr = run_cmd('java "-Dfile.encoding=UTF-8" -cp bin com.dpi.engine.DPIEngine test_dpi.pcap out1.pcap --block-app YouTube --block-ip 192.168.1.50')
for line in stdout.splitlines():
    if 'Forwarded:' in line or 'Dropped:' in line or 'Output written to:' in line:
        print(line)

print("\n--- CHECK 2: MultiThreadedDPIEngine with RULES (threads 4) ---")
code, stdout, stderr = run_cmd('java "-Dfile.encoding=UTF-8" -cp bin com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap out2.pcap --threads 4 --block-app YouTube --block-ip 192.168.1.50')
for line in stdout.splitlines():
    if 'Forwarded:' in line or 'Dropped:' in line or 'Output written to:' in line:
        print(line)

print("\n--- CHECK 3: MultiThreadedDPIEngine across threads 1, 2, 4, 8, 16 ---")
for t in [1, 2, 4, 8, 16]:
    code, stdout, stderr = run_cmd(f'java "-Dfile.encoding=UTF-8" -cp bin com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap out_t{t}.pcap --threads {t} --block-app YouTube --block-ip 192.168.1.50')
    f_line = [l.strip() for l in stdout.splitlines() if 'Forwarded:' in l][0]
    d_line = [l.strip() for l in stdout.splitlines() if 'Dropped:' in l][0]
    print(f"threads={t}: {f_line}, {d_line}")

print("\n--- CHECK 4: Both engines, no rules ---")
code, stdout1, _ = run_cmd('java "-Dfile.encoding=UTF-8" -cp bin com.dpi.engine.DPIEngine test_dpi.pcap out_norules1.pcap')
code, stdout2, _ = run_cmd('java "-Dfile.encoding=UTF-8" -cp bin com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap out_norules2.pcap --threads 4')
print("Single:", [l.strip() for l in stdout1.splitlines() if 'Forwarded:' in l or 'Dropped:' in l])
print("Multi:", [l.strip() for l in stdout2.splitlines() if 'Forwarded:' in l or 'Dropped:' in l])

print("\n--- CHECK 5 & 6: Output file sizes and PCAP validity ---")
os.system("python verify_pcap.py out1.pcap out2.pcap")

print("\n--- CHECK 7: --block-ip 192.168.1.50 alone ---")
code, stdout1, _ = run_cmd('java "-Dfile.encoding=UTF-8" -cp bin com.dpi.engine.DPIEngine test_dpi.pcap out_ip1.pcap --block-ip 192.168.1.50')
code, stdout2, _ = run_cmd('java "-Dfile.encoding=UTF-8" -cp bin com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap out_ip2.pcap --threads 4 --block-ip 192.168.1.50')
print("Single:", [l.strip() for l in stdout1.splitlines() if 'Forwarded:' in l or 'Dropped:' in l])
print("Multi:", [l.strip() for l in stdout2.splitlines() if 'Forwarded:' in l or 'Dropped:' in l])

print("\n--- CHECK 8: --block-app Netflx invalid app ---")
code, stdout, stderr = run_cmd('java "-Dfile.encoding=UTF-8" -cp bin com.dpi.engine.DPIEngine test_dpi.pcap out_err.pcap --block-app Netflx')
print(f"Exit code: {code}")
print("Stderr:", stderr.strip())
