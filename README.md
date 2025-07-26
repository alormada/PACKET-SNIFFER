# PACKET-SNIFFER GUI

Graficzny sniffer pakietów oparty na bibliotece **Tkinter** i **Scapy**, umożliwiający:
- automatyczne wykrywanie urządzeń w lokalnej sieci LAN,
- podgląd informacji o urządzeniach (IP, MAC, producent),
- monitorowanie ilości pakietów wysłanych i odebranych przez wybrane urządzenie w czasie rzeczywistym.

---

<img width="1078" height="690" alt="image" src="https://github.com/user-attachments/assets/2312e31f-3a39-469b-8ab1-1107ea6b2ecc" />


---

## Wymagania

- Python 3.8+
- System operacyjny: Linux (np. Ubuntu)
- Uprawnienia administratora (dla sniffowania pakietów)

---

## Uruchamianie

```bash
sudo python3 main.py
```

>  **Uwaga:** Sniffowanie pakietów wymaga uruchomienia programu z uprawnieniami `sudo`.

---

## Funkcje

*  Automatyczne skanowanie sieci lokalnej i wykrywanie hostów (ARP scan)
*  Pobieranie nazwy producenta karty sieciowej (via MAC Vendors API)
*  Przejrzysty interfejs GUI z listą urządzeń
*  Ręczne lub automatyczne odświeżanie urządzeń
*  Sniffowanie i zliczanie pakietów wysyłanych/odbieranych przez wskazany host
*  Przegląd surowych danych pakietów w czasie rzeczywistym

---

## Struktura

* `main.py` – główny plik aplikacji GUI
* Brak zewnętrznych plików — aplikacja działa samodzielnie po zainstalowaniu zależności.

---

## Bezpieczeństwo i prywatność

Ten sniffer działa **tylko lokalnie** i nie przechwytuje danych poza Twoją siecią. Nie jest przeznaczony do inwigilacji — wyłącznie do edukacji i diagnostyki sieciowej.

---

## Licencja

Projekt open-source — MIT License.

---

## Autor

GitHub: [@alormada](https://github.com/alormada)

---

## ❓ FAQ

**Q: Nie widzę żadnych urządzeń.**
A: Upewnij się, że jesteś połączony z siecią lokalną i masz uprawnienia `sudo`.

**Q: Aplikacja nie uruchamia się na Windows.**
A: To narzędzie przeznaczone głównie dla systemów Linux (np. Ubuntu). Scapy ma ograniczoną funkcjonalność na Windowsie.

