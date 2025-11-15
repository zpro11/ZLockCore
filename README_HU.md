# ZLockCore — Vault Manager

ZLockCore egy grafikus, jelszóval és opcionális recovery kulccsal védett fájlszéf-kezelő alkalmazás Windowsra. A program lehetővé teszi titkosított széfek létrehozását, fájlok biztonságos tárolását, valamint a széfek feloldását, lezárását, importálását, átnevezését és törlését.

## Fő funkciók
- Több széf kezelése, mindegyik külön mappában
- Fájlok titkosítása és visszafejtése AES-GCM algoritmussal
- Jelszavas és recovery kulcsos (szólistás) védelem
- Fájlok hozzáadása, visszaállítása, széfek importálása/exportálása
- Jelszó visszaállítása recovery kulccsal
- Modern, magyar nyelvű grafikus felület (Tkinter)
- Pyinstaller-el készített futtatható .exe fájl.

## Az exe manuális elkészítése
```sh
   pip install pyinstaller
   ```

```sh
   pyinstaller --clean --onefile --noconsole --noupx --icon=icon.ico main.py
   ```

## Futtatás
1. **Python 3.8+ szükséges**
2. Telepítsd a szükséges csomagokat:
   ```sh
   pip install cryptography
   ```
3. Futtasd a programot:
   ```sh
   python main.py
   ```

Vagy szimplán futtasd a ZLockCore.exe-t vagy a ZLockCore_installer.exe-t

## Használat
1. **Új széf létrehozása**
   - Kattints az "Új széf" gombra
   - Adj nevet, válassz mappát, állíts be jelszót
   - (Ajánlott) Recovery kulcs generálása: ezt írd le vagy mentsd el biztonságos helyre!
2. **Széf feloldása**
   - Válaszd ki a széfet, majd kattints a "Feloldás" gombra, add meg a jelszót
3. **Fájlok hozzáadása**
   - Feloldott széf esetén kattints a "Fájlok hozzáadása" gombra, válaszd ki a fájlokat
4. **Széf lezárása**
   - Kattints a "Lezárás" gombra. A fájlok ismét titkosításra kerülnek
5. **Széf megnyitása**
   - Feloldott széf esetén kattints a "Széf megjelenítése" gombra
6. **Jelszó visszaállítása**
   - "Jelszó visszaállítása" gomb, recovery kulcs megadása után új jelszó állítható be
7. **Széf importálása/átnevezése/törlése**
   - A bal oldali listában válaszd ki a széfet, majd a megfelelő gombot

## Fájlstruktúra
- Minden széf egy külön mappában található
- Titkosított fájlok: `storage/` mappában, `.cbox` kiterjesztéssel
- Visszafejtett fájlok: `plain/` mappában (csak feloldás után)
- Metaadatok: `vault.meta.json`, `vault_status.json`

## Biztonsági tanácsok
- Recovery kulcsot mindig mentsd el biztonságos helyre!
- A széf mappáját ne oszd meg, ne tárold nyilvános helyen!
- A program nem tudja visszaállítani a jelszót recovery kulcs nélkül!

## Licenc
Lásd: LICENSE.txt

## Fejlesztői információk
- Fő fájl: `main.py`
- Titkosítás: Scrypt KDF + AES-GCM
- GUI: Tkinter

## Többnyelvűség (nyelvválasztás)

A program több nyelvet is támogat. Alapértelmezés szerint angol és magyar nyelv közül lehet választani.

Nyelvet a jobb felső sarokban található "Language" menü alatt lehet választani. A kiválasztott nyelv elmentésre kerül, és a program újraindítás után is megjegyzi.

### Saját vagy további nyelvek hozzáadása

Ha szeretnél további nyelveket hozzáadni/használni, tölsd le a `more_languages.json` nevű fájlt, és rakd abba a mappába, ahol a `main.py` vagy a `ZLockCore.exe` található. (A ZLockCore_installer automatikusan telepíti a more_laungages.json fájlt a program mappájába)

Ha ez a fájl jelen van, a program automatikusan felkínálja a benne szereplő nyelveket is a menüben. Ha nincs, akkor csak az alapértelmezett angol és magyar közül lehet választani.

---

**Készítette: Gódor Zoárd a ZLockCore fejlesztője**
