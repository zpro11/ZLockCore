#!/usr/bin/env python3
import os, sys, json, base64, secrets, threading, shutil
from pathlib import Path
from tkinter import *
from tkinter import ttk, filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
SCRYPT_PARAMS = dict(length=32, n=2**14, r=8, p=1)
MASTER_KEY_LEN = 32
NONCE_SIZE = 12
STORAGE_EXT = '.cbox'
META_EXT = '.meta.json'
VAULT_META = 'vault.meta.json'
PLAIN_DIRNAME = 'plain'
STORAGE_DIRNAME = 'storage'
VAULT_STATUS = 'vault_status.json'

def get_app_meta_path():
    appdata = Path(os.getenv('APPDATA') or Path.home())
    meta_dir = appdata / 'ZLockCore'
    meta_dir.mkdir(parents=True, exist_ok=True)
    return meta_dir / 'zlockcore_manager.json'

APP_META = get_app_meta_path()

def set_hidden_windows(path: Path):
    try:
        import ctypes
        ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x02)
    except Exception:
        pass
def restrict_acl_to_current_user(path: Path):
    try:
        import getpass, subprocess
        user = getpass.getuser()
        subprocess.run(['icacls', str(path), '/inheritance:r'], check=False)
        subprocess.run(['icacls', str(path), '/grant:r', f'{user}:F'], check=False)
    except Exception:
        pass

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, **SCRYPT_PARAMS)
    return kdf.derive(password.encode('utf-8'))

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct

def aes_decrypt(key: bytes, blob: bytes) -> bytes:
    nonce = blob[:NONCE_SIZE]
    ct = blob[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

def load_app_meta():
    if APP_META.exists():
        try:
            return json.loads(APP_META.read_text(encoding='utf-8'))
        except Exception:
            return {}
    return {}

def save_app_meta(m):
    APP_META.parent.mkdir(parents=True, exist_ok=True)
    APP_META.write_text(json.dumps(m, indent=2), encoding='utf-8')

def create_vault_meta(vault_root: Path, master_key: bytes, password: str, recovery_phrase: str = None, description: str = None):
    salt_pwd = secrets.token_bytes(16)
    key_pwd = derive_key(password, salt_pwd)
    enc_master_pwd = aes_encrypt(key_pwd, master_key)
    meta = {
        'enc_master_pwd': base64.b64encode(enc_master_pwd).decode('ascii'),
        'salt_pwd': base64.b64encode(salt_pwd).decode('ascii'),
        'recovery_enabled': False
    }
    if recovery_phrase:
        salt_rec = secrets.token_bytes(16)
        key_rec = derive_key(recovery_phrase, salt_rec)
        enc_master_rec = aes_encrypt(key_rec, master_key)
        meta['recovery_enabled'] = True
        meta['enc_master_rec'] = base64.b64encode(enc_master_rec).decode('ascii')
        meta['salt_rec'] = base64.b64encode(salt_rec).decode('ascii')
    if description:
        meta['description'] = description
    with open(vault_root / VAULT_META, 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=2)
    return meta

def load_vault_meta(vault_root: Path):
    f = vault_root / VAULT_META
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding='utf-8'))
    except Exception:
        return None

def update_vault_meta(vault_root: Path, meta: dict):
    with open(vault_root / VAULT_META, 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=2)

def store_plain_file_to_vault(vault_root: Path, master_key: bytes, plain_path: Path):
    storage_dir = vault_root / STORAGE_DIRNAME
    storage_dir.mkdir(parents=True, exist_ok=True)
    file_id = secrets.token_hex(12)
    storage_file = storage_dir / (file_id + STORAGE_EXT)
    meta_file = storage_dir / (file_id + META_EXT)
    file_key = secrets.token_bytes(MASTER_KEY_LEN)
    with open(plain_path, 'rb') as f:
        data = f.read()
    file_nonce = secrets.token_bytes(NONCE_SIZE)
    aesf = AESGCM(file_key)
    ct = aesf.encrypt(file_nonce, data, None)
    storage_file.write_bytes(file_nonce + ct)
    enc_file_key = aes_encrypt(master_key, file_key)
    enc_name = aes_encrypt(master_key, plain_path.name.encode('utf-8'))
    meta = {
        'enc_file_key': base64.b64encode(enc_file_key).decode('ascii'),
        'enc_name': base64.b64encode(enc_name).decode('ascii')
    }
    meta_file.write_text(json.dumps(meta, indent=2), encoding='utf-8')
    try:
        plain_path.unlink()
    except Exception:
        pass

def decrypt_all_to_plain(vault_root: Path, master_key: bytes):
    storage_dir = vault_root / STORAGE_DIRNAME
    plain_dir = vault_root / PLAIN_DIRNAME
    plain_dir.mkdir(parents=True, exist_ok=True)
    if not storage_dir.exists():
        return
    
    meta_files = list(storage_dir.glob('*' + META_EXT))
    
    for meta_path in meta_files:
        try:
            meta = json.loads(meta_path.read_text(encoding='utf-8'))
            enc_name = base64.b64decode(meta['enc_name'])
            name = aes_decrypt(master_key, enc_name).decode('utf-8')
            file_id = meta_path.name.replace(META_EXT, '')
            storage_file = storage_dir / (file_id + STORAGE_EXT)
            if not storage_file.exists():
                continue
            blob = storage_file.read_bytes()
            nonce = blob[:NONCE_SIZE]
            ct = blob[NONCE_SIZE:]
            file_key_enc = base64.b64decode(meta['enc_file_key'])
            file_key = aes_decrypt(master_key, file_key_enc)
            aesf = AESGCM(file_key)
            data = aesf.decrypt(nonce, ct, None)
            out_path = plain_dir / name
            i = 1
            base = name
            while out_path.exists():
                out_path = plain_dir / f"{Path(base).stem}_{i}{Path(base).suffix}"
                i += 1
            out_path.write_bytes(data)
        except Exception as e:
            continue

def encrypt_plain_back_and_cleanup(vault_root: Path, master_key: bytes):
    plain_dir = vault_root / PLAIN_DIRNAME
    if not plain_dir.exists():
        return
    def encrypt_recursive(path):
        if path.is_file():
            store_plain_file_to_vault(vault_root, master_key, path)
        elif path.is_dir():
            for child in list(path.iterdir()):
                encrypt_recursive(child)
            try:
                if not any(path.iterdir()):
                    path.rmdir()
            except Exception:
                pass
    encrypt_recursive(plain_dir)
    try:
        if not any(plain_dir.iterdir()):
            plain_dir.rmdir()
    except Exception:
        pass


WORDLIST = [
    'alma','haza','tree','river','sun','moon','star','konyv','book','glass','fire','stone','kecske',
    'bus','train','guitar','plane','cloud','szel','nap','hold','light','shadow','key','road',
    'dream','music','garden','bolt','apple','door','window','riverbank','sky','oak','maple','leaf',
    'asztal','szék','tenger','hegy','víz','föld','szív','csillag','toll','papír','ceruza','szám',
    'kép','fal','ablak','szoba','kert','virág','madár','kutya','macska','egér','ló','hal','szél',
    'villám','eső','hó','jég','tűz','por','homok','kő','gyémánt','arany','ezüst','bronz','vas',
    'réz','fa','bokor','levél','gyökér','ág','gyümölcs','bogyó','szőlő','barack','körte','cseresznye',
    'meggy','dió','mogyoró','mandula','pisztácia','füge','datolya','banán','narancs','citrom','lime',
    'gránát','szilva','eper','málna','ribizli','áfonya','szeder','földi','tó','patak','folyó','óceán',
    'tengerpart','sziget','félsziget','domb','völgy','sivatag','erdő','puszta','mező','rét','sztyepp',
    'város','falu','utca','tér','park','híd','torony','templom','kastély','palota','ház','lakás',
    'szoba','konyha','fürdő','kamra','padlás','pince','garázs','udvar','kert','terasz','erkély',
    'lépcső','folyosó','ajtó','kapu','kerítés','zár','kulcs','kilincs','ablak','redőny','függöny',
    'asztal','szék','kanapé','fotel','ágy','matrac','párna','takaró','lepedő','szőnyeg','padló',
    'fal','plafon','lámpa','csillár','villany','konnektor','kapcsoló','óra','naptár','tükör','kép',
    'polc','szekrény','fiók','doboz','kosár','táska','bőrönd','zseb','kabát','nadrág','ing','póló',
    'pulóver','cipő','csizma','papucs','zokni','kesztyű','sál','sapka','kalap','öv','nyakkendő',
    'óra','lánc','gyűrű','karkötő','medál','bross','csipesz','gomb','cipzár','patent','csat','tépőzár',
    'számítógép','telefon','tablet','monitor','billentyűzet','egér','hangszóró','mikrofon','kamera',
    'nyomtató','szkenner','router','modem','kábel','csatlakozó','akkumulátor','elem','töltő','adapter',
    'program','fájl','mappa','adat','jelszó','kód','titok','biztonság','védelem','mentés','visszaállítás',
    'hiba','figyelmeztetés','üzenet','jel','ikon','gomb','ablak','menü','lista','tábla','diagram','grafikon',
    'szám','betű','karakter','szó','mondat','bekezdés','oldal','könyv','füzet','jegyzet','napló','levél',
    'email','posta','csomag','küldemény','futár','szállítás','raktár','bolt','áruház','piac','vásár',
    'pénz','bank','számla','kártya','érme','bankjegy','utalvány','kupon','jegy','bérlet','bizonylat',
    'számla','nyugta','csekk','szerződés','biztosítás','engedély','igazolvány','útlevél','vízum','jegyzőkönyv',
    'dokumentum','irat','okmány','pecsét','aláírás','bélyeg','matrica','jelvény','kitűző','kártya','token',
    'szám','kód','azonosító','jelszó','titok','kulcs','hash','salt','nonce','cipher','crypto','vault',
    'safe','lock','unlock','open','close','store','retrieve','backup','restore','delete','remove','add',
    'update','edit','change','modify','create','new','old','first','last','next','previous','random','secure',
    'strong','weak','easy','hard','simple','complex','fast','slow','quick','long','short','big','small',
    'high','low','up','down','left','right','center','middle','top','bottom','front','back','side','edge',
    'corner','point','line','curve','circle','square','rectangle','triangle','polygon','shape','form','figure',
    'object','item','element','part','piece','section','segment','block','unit','group','set','list','array',
    'table','matrix','vector','number','digit','letter','symbol','sign','mark','code','text','data','info',
    'message','note','comment','hint','tip','help','guide','manual','book','article','paper','report','review',
    'test','exam','quiz','question','answer','solution','result','score','grade','level','stage','step','phase',
    'plan','project','task','goal','aim','target','purpose','reason','cause','effect','result','outcome','impact',
    'change','move','shift','turn','rotate','flip','reverse','swap','exchange','replace','remove','delete','add',
    'insert','append','join','split','divide','multiply','subtract','plus','minus','times','divide','equal','not',
    'yes','no','true','false','on','off','in','out','with','without','for','against','by','from','to','at','of',
    'and','or','but','if','else','then','when','while','until','before','after','since','because','so','as','like',
    'about','above','below','over','under','between','among','through','across','along','around','near','far','close',
    'open','close','start','stop','begin','end','finish','complete','continue','pause','wait','sleep','wake','run',
    'walk','jump','fly','drive','ride','swim','climb','crawl','slide','roll','throw','catch','hit','kick','push',
    'pull','lift','drop','hold','touch','feel','see','hear','smell','taste','think','know','learn','understand',
    'remember','forget','imagine','dream','wish','hope','want','need','like','love','hate','prefer','choose','pick',
    'find','lose','get','give','send','receive','buy','sell','pay','cost','spend','save','waste','earn','win','lose',
    'play','work','study','teach','train','practice','exercise','rest','relax','enjoy','celebrate','party','meet',
    'visit','travel','tour','explore','discover','search','look','watch','listen','read','write','draw','paint',
    'build','make','create','design','develop','produce','manufacture','construct','assemble','install','setup',
    'fix','repair','break','damage','destroy','protect','defend','attack','fight','win','lose','score','goal',
    'team','group','club','crew','band','class','course','school','college','university','academy','center','office',
    'room','hall','lab','studio','shop','store','market','mall','plaza','park','garden','yard','field','farm',
    'forest','woods','mountain','hill','valley','plain','desert','island','lake','river','sea','ocean','beach',
    'coast','shore','port','harbor','dock','pier','bridge','road','street','lane','avenue','boulevard','drive',
    'way','path','trail','route','track','line','rail','station','stop','terminal','airport','plane','train','bus',
    'car','bike','motor','cycle','truck','van','taxi','boat','ship','subway','metro','tram','ferry','rocket','satellite',
    'space','star','planet','moon','sun','sky','cloud','rain','snow','storm','wind','fog','mist','ice','fire','water',
    'earth','ground','soil','rock','sand','dust','mud','clay','stone','pebble','boulder','crystal','gem','diamond',
    'gold','silver','bronze','copper','iron','steel','metal','wood','plastic','glass','paper','card','cloth','fabric',
    'thread','string','rope','wire','chain','belt','pipe','tube','bar','rod','stick','pole','beam','board','panel',
    'sheet','plate','disk','ring','ball','cube','box','case','bag','pack','kit','tool','device','machine','engine',
    'motor','pump','fan','light','lamp','bulb','switch','button','key','lock','handle','knob','lever','gear','wheel',
    'axle','shaft','spring','valve','filter','screen','cover','lid','cap','plug','socket','joint','hinge','clip','pin',
    'screw','nut','bolt','nail','rivet','staple','tack','glue','tape','paint','ink','oil','grease','fuel','gas','air',
    'power','energy','force','heat','cold','sound','noise','voice','music','song','melody','tune','beat','rhythm',
    'note','chord','scale','band','orchestra','choir','group','solo','duet','trio','quartet','quintet','singer','player',
    'artist','actor','dancer','writer','author','poet','painter','sculptor','designer','director','producer','editor',
    'manager','leader','chief','boss','head','owner','partner','member','guest','visitor','client','customer','user',
    'admin','staff','worker','employee','teacher','student','doctor','nurse','patient','driver','pilot','captain','officer',
    'soldier','guard','police','fireman','engineer','scientist','researcher','expert','specialist','technician','mechanic',
    'builder','maker','creator','inventor','innovator','founder','organizer','planner','helper','supporter','friend','family',
    'parent','child','son','daughter','brother','sister','husband','wife','uncle','aunt','cousin','grandparent','grandchild',
    'baby','kid','teen','adult','elder','man','woman','boy','girl','person','people','group','crowd','team','community',
    'society','nation','country','state','city','town','village','region','area','zone','district','province','territory',
    'continent','world','earth','globe','planet','universe','space','galaxy','star','sun','moon','comet','asteroid','meteor',
    'orbit','axis','pole','equator','hemisphere','latitude','longitude','altitude','depth','distance','length','width','height',
    'size','volume','mass','weight','speed','velocity','acceleration','direction','angle','degree','minute','second','hour',
    'day','week','month','year','decade','century','millennium','age','era','period','epoch','season','spring','summer','autumn','winter'
]

def generate_recovery_phrase(n=24):
    return ' '.join(secrets.choice(WORDLIST) for _ in range(n))

app_meta = load_app_meta()
def load_vault_status(vault_root: Path):
    status_file = vault_root / VAULT_STATUS
    if status_file.exists():
        try:
            return json.loads(status_file.read_text(encoding='utf-8'))
        except Exception:
            return {"unlocked": False}
    return {"unlocked": False}

def save_vault_status(vault_root: Path, unlocked: bool):
    status_file = vault_root / VAULT_STATUS
    status = {"unlocked": unlocked}
    status_file.write_text(json.dumps(status), encoding='utf-8')


import platform
class Translator:
    def __init__(self):
        self.translations = {
            'hu': {
                'title': 'ZLockCore — Széfkezelő',
                'vaults': 'Széfek',
                'new_vault': 'Új széf',
                'import': 'Importálás',
                'rename': 'Átnevezés',
                'delete': 'Törlés',
                'details': 'Széf részletek',
                'name': 'Név',
                'desc': 'Leírás',
                'path': 'Útvonal',
                'status': 'Státusz',
                'unlocked': 'Feloldva ✓',
                'locked': 'Lezárva',
                'unlock': 'Feloldás',
                'open': 'Széf megjelenítése',
                'lock': 'Lezárás',
                'recover': 'Jelszó visszaállítása',
                'menu_language': 'Nyelv',
                'english': 'Angol',
                'hungarian': 'Magyar',
                'error': 'Hiba',
                'ok': 'OK',
                'cancel': 'Mégse',
                'yes': 'Igen',
                'no': 'Nem',
                'info': 'Info',
                'confirm': 'Megerősítés',
                'password': 'Jelszó',
                'password_confirm': 'Erősítsd meg a jelszót:',
                'password_enter': 'Add meg a jelszót:',
                'password_empty': 'A jelszó nem lehet üres!',
                'passwords_not_match': 'A jelszavak nem egyeznek!',
                'vault_name_exists': 'Ez a név már létezik!',
                'vault_name': 'Új széf',
                'vault_name_prompt': 'Adj nevet az új széfnek:',
                'vault_desc': 'Leírás',
                'vault_desc_prompt': 'Adj rövid leírást a széfhez (opcionális):',
                'vault_dir_prompt': 'Válassz egy mappát a széfnek (kötelező):',
                'vault_dir_required': 'Kötelező mappát választani!\n\nSzeretnél újra próbálkozni?',
                'recovery_key': 'Recovery kulcs',
                'recovery_key_prompt': 'Szeretnél recovery kulcsot használni? (Ez arra van, hogy jelszó elvesztése esetén vissza tudd állítani a hozzáférést.) Nagyon, nagyon, nagyon ajánlott az igen-re nyomni!',
                'recovery_key_info': 'Recovery kulcs (Helyezd biztonságos helyre! Vagy papíron, pendrive-on legyen, és ne ossza meg senkivel!):',
                'copy_to_clipboard': 'Másolás vágólapra',
                'done': 'Kész',
                'vault_created': 'Széf létrehozva: {vault_name}',
                'select_vault': 'Válassz egy széfet!',
                'already_unlocked': 'A széf már fel van oldva! (vault_status.json)',
                'unlock_failed': 'A feloldás sikertelen: {error}',
                'meta_load_failed': 'Nem lehet betölteni a széf metaadatait!',
                'lock_pw_needed': 'Lezárás - jelszó szükséges, mert a program újraindult',
                'lock_failed': 'A lezárás sikertelen, hibás jelszó vagy metaadat: {error}',
                'not_selected': 'Nincs kiválasztva széf!',
                'lock_first': 'Előbb zárja le a széfet, majd oldja fel újra!',
                'open_failed': 'Nem lehet megnyitni a széfet: {error}',
                'no_recovery': 'Ennek a széfnek nincs recovery kulcsa beállítva!',
                'recovery_empty': 'A recovery kulcs nem lehet üres!',
                'new_password': 'Új jelszó',
                'enter_new_password': 'Add meg az új jelszót:',
                'password_updated': 'A jelszó sikeresen frissítve!',
                'recovery_failed': 'A helyreállítás sikertelen: {error}',
                'import_vault_dir': 'Válassz egy széf mappát az importáláshoz',
                'not_valid_vault': 'Ez nem egy érvényes széf mappa!',
                'vault_exists': "A '{vault_name}' nevű széf már létezik!",
                'import_success': "A széf sikeresen importálva: {vault_name}",
                'import_failed': "Az importálás sikertelen!\nMappa: {vault_path}\nHiba: {error}",
                'delete_select': 'Válassz egy széfet a törléshez!',
                'delete_confirm': "Biztosan törölni szeretnéd a '{vault_name}' széfet?\nEz nem vonható vissza!",
                'delete_success': "A '{vault_name}' széf sikeresen törölve!",
                'delete_failed': 'A törlés sikertelen: {error}',
                'rename_select': 'Válassz egy széfet az átnevezéshez!',
                'rename_title': 'Széf átnevezése',
                'rename_prompt': "Add meg az új nevet a '{vault_name}' széfnek:",
                'rename_exists': 'Ez a név már létezik!',
                'rename_success': "A széf sikeresen átnevezve: {new_name}",
                'rename_failed': 'Az átnevezés sikertelen: {error}',
            },
            'en': {
                'title': 'ZLockCore — Vault Manager',
                'vaults': 'Vaults',
                'new_vault': 'New Vault',
                'import': 'Import',
                'rename': 'Rename',
                'delete': 'Delete',
                'details': 'Vault Details',
                'name': 'Name',
                'desc': 'Description',
                'path': 'Path',
                'status': 'Status',
                'unlocked': 'Unlocked ✓',
                'locked': 'Locked',
                'unlock': 'Unlock',
                'open': 'Show Vault',
                'lock': 'Lock',
                'recover': 'Password Recovery',
                'menu_language': 'Language',
                'english': 'English',
                'hungarian': 'Hungarian',
                'error': 'Error',
                'ok': 'OK',
                'cancel': 'Cancel',
                'yes': 'Yes',
                'no': 'No',
                'info': 'Info',
                'confirm': 'Confirmation',
                'password': 'Password',
                'password_confirm': 'Confirm password:',
                'password_enter': 'Enter password:',
                'password_empty': 'Password cannot be empty!',
                'passwords_not_match': 'Passwords do not match!',
                'vault_name_exists': 'This name already exists!',
                'vault_name': 'New Vault',
                'vault_name_prompt': 'Enter a name for the new vault:',
                'vault_desc': 'Description',
                'vault_desc_prompt': 'Enter a short description for the vault (optional):',
                'vault_dir_prompt': 'Select a folder for the vault (required):',
                'vault_dir_required': 'You must select a folder!\n\nWould you like to try again?',
                'recovery_key': 'Recovery key',
                'recovery_key_prompt': 'Would you like to use a recovery key? (This is for regaining access if you lose your password. It is highly recommended to choose Yes!)',
                'recovery_key_info': 'Recovery key (Store it in a safe place! On paper or a USB drive, and do not share it with anyone!):',
                'copy_to_clipboard': 'Copy to clipboard',
                'done': 'Done',
                'vault_created': 'Vault created: {vault_name}',
                'select_vault': 'Select a vault!',
                'already_unlocked': 'The vault is already unlocked! (vault_status.json)',
                'unlock_failed': 'Unlock failed: {error}',
                'meta_load_failed': 'Could not load vault metadata!',
                'lock_pw_needed': 'Lock - password required because the program was restarted',
                'lock_failed': 'Lock failed, wrong password or metadata: {error}',
                'not_selected': 'No vault selected!',
                'lock_first': 'Please lock the vault first, then unlock again!',
                'open_failed': 'Could not open the vault: {error}',
                'no_recovery': 'This vault does not have a recovery key set!',
                'recovery_empty': 'Recovery key cannot be empty!',
                'new_password': 'New password',
                'enter_new_password': 'Enter the new password:',
                'password_updated': 'Password updated successfully!',
                'recovery_failed': 'Recovery failed: {error}',
                'import_vault_dir': 'Select a vault folder to import',
                'not_valid_vault': 'This is not a valid vault folder!',
                'vault_exists': "A vault named '{vault_name}' already exists!",
                'import_success': "Vault imported successfully: {vault_name}",
                'import_failed': "Import failed!\nFolder: {vault_path}\nError: {error}",
                'delete_select': 'Select a vault to delete!',
                'delete_confirm': "Are you sure you want to delete the vault '{vault_name}'?\nThis cannot be undone!",
                'delete_success': "Vault deleted successfully: {vault_name}",
                'delete_failed': 'Delete failed: {error}',
                'rename_select': 'Select a vault to rename!',
                'rename_title': 'Rename vault',
                'rename_prompt': "Enter a new name for the vault '{vault_name}':",
                'rename_exists': 'This name already exists!',
                'rename_success': "Vault renamed successfully: {new_name}",
                'rename_failed': 'Rename failed: {error}',
            }
        }
        self._load_more_languages()
        self.language = 'hu'
        self.config_path = self._get_config_path()
        self._load_language()

    def _load_more_languages(self):
        prog_dir = os.path.dirname(sys.argv[0])
        lang_path = os.path.join(prog_dir, 'more_languages.json')
        if os.path.isfile(lang_path):
            try:
                with open(lang_path, 'r', encoding='utf-8') as f:
                    langs = json.load(f)
                    if isinstance(langs, dict):
                        self.translations.update(langs)
            except Exception:
                pass

    def _get_config_path(self):
        if platform.system() == 'Windows':
            appdata = os.getenv('APPDATA')
        else:
            appdata = os.path.expanduser('~/.config')
        config_dir = os.path.join(appdata, 'zlockcore')
        os.makedirs(config_dir, exist_ok=True)
        return os.path.join(config_dir, 'settings.json')

    def _save_language(self):
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump({'language': self.language}, f)
        except Exception:
            pass

    def _load_language(self):
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if 'language' in data:
                    self.language = data['language']
        except Exception:
            self.language = 'hu'

    def t(self, key):
        return self.translations.get(self.language, {}).get(key, key)

    def set_language(self, lang):
        self.language = lang
        self._save_language()

translator = Translator()
def _t(key):
    return translator.t(key)

BG = '#eaf2ff'
ACCENT = '#2b66d6'
BTN_BG = '#2b66d6'
BTN_FG = 'white'
FONT = ('Segoe UI', 10)

root = Tk()
root.title(_t('title'))
root.geometry('1400x600')
root.configure(bg=BG)

def _set_language(lang):
    translator.set_language(lang)
    _refresh_ui_texts()

def _refresh_ui_texts():
    root.title(_t('title'))
    left_label.config(text=_t('vaults'))
    btn_new.config(text=_t('new_vault'))
    btn_import.config(text=_t('import'))
    btn_rename.config(text=_t('rename'))
    btn_delete.config(text=_t('delete'))
    right_label.config(text=_t('details'))
    info_name.config(text=f"{_t('name')}: —")
    info_desc.config(text=f"{_t('desc')}: ")
    info_path.config(text=f"{_t('path')}: ")
    status_lbl.config(text=f"{_t('status')}: -")
    unlock_btn.config(text=_t('unlock'))
    open_btn.config(text=_t('open'))
    lock_btn.config(text=_t('lock'))
    recover_btn.config(text=_t('recover'))

    root.update_idletasks()
    left_panel_width = left.winfo_reqwidth() if left.winfo_ismapped() else 300
    right_panel_width = right.winfo_reqwidth() if 'right' in globals() and right.winfo_ismapped() else 600
    min_width = max(left_panel_width + right_panel_width + 60, 800)
    min_height = 600
    root.geometry(f"{min_width}x{min_height}")

menubar = Menu(root)
lang_menu = Menu(menubar, tearoff=0)
lang_var = StringVar(value=translator.language)
for lang_code in translator.translations.keys():
    lang_menu.add_radiobutton(label=lang_code, value=lang_code, variable=lang_var, command=lambda c=lang_code: _set_language(c))
menubar.add_cascade(label='Language', menu=lang_menu)
root.config(menu=menubar)


left = Frame(root, bg=BG)
left.pack(side=LEFT, fill=BOTH, padx=12, pady=12)
left_label = Label(left, text=_t('vaults'), bg=BG, fg='black', font=('Segoe UI', 12, 'bold'))
left_label.pack(anchor='w')
vault_listbox = Listbox(left, width=32, height=25, font=FONT)
vault_listbox.pack(pady=8, fill=BOTH, expand=True)

btn_frame = Frame(left, bg=BG, height=100)
btn_frame.pack(fill=X, pady=6)


def mkbtn(parent, text, cmd):
    b = Button(parent, text=text, command=cmd, bg=BTN_BG, fg=BTN_FG, relief='flat', activebackground=ACCENT, font=FONT, height=2)
    return b

def ask_password_with_confirm(parent=None, title=None):
    def get_password():
        win = Toplevel(parent)
        win.title(_t('password'))
        win.transient(parent)
        win.grab_set()
        win.resizable(False, False)
        pw_var = StringVar()
        confirm_var = StringVar()
        show_pw = BooleanVar(value=False)
        show_confirm = BooleanVar(value=False)

        def toggle_pw(event=None):
            pw_entry.config(show='' if show_pw.get() else '*')
        def toggle_confirm(event=None):
            confirm_entry.config(show='' if show_confirm.get() else '*')

        Label(win, text=_t('password_enter'), font=FONT).grid(row=0, column=0, sticky='w', padx=8, pady=8)
        pw_entry = Entry(win, textvariable=pw_var, show='*', font=FONT, width=24)
        pw_entry.grid(row=0, column=1, padx=8, pady=8)
        pw_eye = Button(win, text='👁', relief='flat', font=FONT, width=2)
        pw_eye.grid(row=0, column=2, padx=2)
        pw_eye.bind('<ButtonPress-1>', lambda e: show_pw.set(True) or toggle_pw())
        pw_eye.bind('<ButtonRelease-1>', lambda e: show_pw.set(False) or toggle_pw())

        Label(win, text=_t('password_confirm'), font=FONT).grid(row=1, column=0, sticky='w', padx=8, pady=8)
        confirm_entry = Entry(win, textvariable=confirm_var, show='*', font=FONT, width=24)
        confirm_entry.grid(row=1, column=1, padx=8, pady=8)
        confirm_eye = Button(win, text='👁', relief='flat', font=FONT, width=2)
        confirm_eye.grid(row=1, column=2, padx=2)
        confirm_eye.bind('<ButtonPress-1>', lambda e: show_confirm.set(True) or toggle_confirm())
        confirm_eye.bind('<ButtonRelease-1>', lambda e: show_confirm.set(False) or toggle_confirm())

        result = {'password': None}

        def ok():
            pw = pw_var.get()
            confirm = confirm_var.get()
            if not pw:
                messagebox.showwarning(_t('error'), _t('password_empty'), parent=win)
                return
            if pw != confirm:
                messagebox.showerror(_t('error'), _t('passwords_not_match'), parent=win)
                return
            result['password'] = pw
            win.destroy()
        def cancel():
            win.destroy()

        Button(win, text=_t('ok'), command=ok, bg=BTN_BG, fg=BTN_FG, font=FONT, width=10).grid(row=2, column=1, pady=12)
        Button(win, text=_t('cancel'), command=cancel, font=FONT, width=10).grid(row=2, column=2, pady=12)
        pw_entry.focus_set()
        win.wait_window()
        return result['password']

    while True:
        password = get_password()
        if password is None:
            return None
        return password

def create_vault_dialog():
    vault_name = simpledialog.askstring(_t('vault_name'), _t('vault_name_prompt'), parent=root)
    if not vault_name:
        return
    if vault_name in app_meta:
        messagebox.showerror(_t('error'), _t('vault_name_exists'))
        return

    description = simpledialog.askstring(_t('vault_desc'), _t('vault_desc_prompt'), parent=root)

    vault_dir = None
    while not vault_dir:
        vault_dir = filedialog.askdirectory(title=_t('vault_dir_prompt'), parent=root)
        if not vault_dir:
            response = messagebox.askyesno(_t('error'), _t('vault_dir_required'), parent=root)
            if not response:
                return
    
    vault_root = Path(vault_dir) / f'ZLockCore_{vault_name}'

    password = ask_password_with_confirm(parent=root)
    if not password:
        return

    use_recovery = messagebox.askyesno(_t('recovery_key'), _t('recovery_key_prompt'))
    recovery_phrase = None
    if use_recovery:
        recovery_phrase = generate_recovery_phrase(24)

    vault_root.mkdir(parents=True, exist_ok=True)

    master_key = secrets.token_bytes(MASTER_KEY_LEN)
    create_vault_meta(vault_root, master_key, password, recovery_phrase, description)

    app_meta[vault_name] = str(vault_root)
    save_app_meta(app_meta)
    refresh_vault_list()
    if recovery_phrase:
        def show_recovery_phrase(phrase):
            win = Toplevel(root)
            win.title(_t('recovery_key'))
            win.transient(root)
            win.grab_set()
            win.resizable(False, False)
            Label(win, text=_t('recovery_key_info'), font=FONT).pack(padx=12, pady=(12,4))
            entry = Entry(win, font=FONT, width=80)
            entry.pack(padx=12, pady=8)
            entry.insert(0, phrase)
            entry.select_range(0, END)
            entry.focus_set()
            def copy():
                win.clipboard_clear()
                win.clipboard_append(phrase)
            Button(win, text=_t('copy_to_clipboard'), command=copy, font=FONT, bg=BTN_BG, fg=BTN_FG).pack(pady=(0,12))
            Button(win, text=_t('ok'), command=win.destroy, font=FONT, width=10).pack(pady=(0,12))
            win.wait_window()
        show_recovery_phrase(recovery_phrase)
        messagebox.showinfo(_t('done'), _t('vault_created').format(vault_name=vault_name))
    else:
        messagebox.showinfo(_t('done'), _t('vault_created').format(vault_name=vault_name))

def unlock_vault():
    global current_vault, unlocked_master_keys
    if not current_vault:
        messagebox.showwarning(_t('error'), _t('select_vault'))
        return
    vault_root = Path(app_meta[current_vault])
    plain_dir = vault_root / PLAIN_DIRNAME
    vault_status = load_vault_status(vault_root)
    if vault_status.get("unlocked", False):
        messagebox.showinfo(_t('info'), _t('already_unlocked'))
        return
    
    def ask_password(title):
        win = Toplevel(root)
        win.title(title)
        win.transient(root)
        win.grab_set()
        win.resizable(False, False)
        pw_var = StringVar()
        show_pw = BooleanVar(value=False)
        Label(win, text=_t('password_enter'), font=FONT).grid(row=0, column=0, sticky='w', padx=8, pady=8)
        pw_entry = Entry(win, textvariable=pw_var, show='*', font=FONT, width=32)
        pw_entry.grid(row=0, column=1, padx=8, pady=8)
        pw_eye = Button(win, text='👁', relief='flat', font=FONT, width=2)
        pw_eye.grid(row=0, column=2, padx=2)
        def toggle_pw(event=None):
            pw_entry.config(show='' if show_pw.get() else '*')
        pw_eye.bind('<ButtonPress-1>', lambda e: show_pw.set(True) or toggle_pw())
        pw_eye.bind('<ButtonRelease-1>', lambda e: show_pw.set(False) or toggle_pw())
        result = {'pw': None}
        def ok():
            val = pw_var.get()
            if not val:
                messagebox.showwarning(_t('error'), _t('password_empty'), parent=win)
                return
            result['pw'] = val
            win.destroy()
        def cancel():
            win.destroy()
        Button(win, text=_t('ok'), command=ok, bg=BTN_BG, fg=BTN_FG, font=FONT, width=10).grid(row=1, column=1, pady=12)
        Button(win, text=_t('cancel'), command=cancel, font=FONT, width=10).grid(row=1, column=2, pady=12)
        pw_entry.focus_set()
        win.wait_window()
        return result['pw']

    password = ask_password(_t('unlock'))
    if not password:
        return

    try:
        vault_meta = load_vault_meta(vault_root)
        if not vault_meta:
            messagebox.showerror(_t('error'), _t('meta_load_failed'))
            return
        salt_pwd = base64.b64decode(vault_meta['salt_pwd'])
        key_pwd = derive_key(password, salt_pwd)
        enc_master_pwd = base64.b64decode(vault_meta['enc_master_pwd'])
        master_key = aes_decrypt(key_pwd, enc_master_pwd)
        unlocked_master_keys[current_vault] = master_key
        plain_dir = vault_root / PLAIN_DIRNAME
        if not plain_dir.exists():
            decrypt_all_to_plain(vault_root, master_key)
            storage_dir = vault_root / STORAGE_DIRNAME
            if storage_dir.exists():
                shutil.rmtree(storage_dir)
        save_vault_status(vault_root, True)
        unlock_btn.config(state='disabled', text=_t('unlocked'))
        open_btn.config(state='normal')
        lock_btn.config(state='normal')
        status_lbl.config(text=f"{_t('status')}: {_t('unlocked')}")
    except Exception as e:
        messagebox.showerror(_t('error'), _t('unlock_failed').format(error=str(e)))

def lock_vault():
    global current_vault, unlocked_master_keys
    if not current_vault:
        return

    vault_root = Path(app_meta[current_vault])
    vault_status = load_vault_status(vault_root)
    did_lock = False
    master_key = None
    if current_vault not in unlocked_master_keys:
        def ask_password(title):
            win = Toplevel(root)
            win.title(title)
            win.transient(root)
            win.grab_set()
            win.resizable(False, False)
            pw_var = StringVar()
            show_pw = BooleanVar(value=False)
            Label(win, text=_t('password_enter'), font=FONT).grid(row=0, column=0, sticky='w', padx=8, pady=8)
            pw_entry = Entry(win, textvariable=pw_var, show='*', font=FONT, width=32)
            pw_entry.grid(row=0, column=1, padx=8, pady=8)
            pw_eye = Button(win, text='👁', relief='flat', font=FONT, width=2)
            pw_eye.grid(row=0, column=2, padx=2)
            def toggle_pw(event=None):
                pw_entry.config(show='' if show_pw.get() else '*')
            pw_eye.bind('<ButtonPress-1>', lambda e: show_pw.set(True) or toggle_pw())
            pw_eye.bind('<ButtonRelease-1>', lambda e: show_pw.set(False) or toggle_pw())
            result = {'pw': None}
            def ok():
                val = pw_var.get()
                if not val:
                    messagebox.showwarning(_t('error'), _t('password_empty'), parent=win)
                    return
                result['pw'] = val
                win.destroy()
            def cancel():
                win.destroy()
            Button(win, text=_t('ok'), command=ok, bg=BTN_BG, fg=BTN_FG, font=FONT, width=10).grid(row=1, column=1, pady=12)
            Button(win, text=_t('cancel'), command=cancel, font=FONT, width=10).grid(row=1, column=2, pady=12)
            pw_entry.focus_set()
            win.wait_window()
            return result['pw']

        password = ask_password(_t('lock_pw_needed'))
        if not password:
            return
        try:
            vault_meta = load_vault_meta(vault_root)
            if not vault_meta:
                messagebox.showerror(_t('error'), _t('meta_load_failed'))
                return
            salt_pwd = base64.b64decode(vault_meta['salt_pwd'])
            key_pwd = derive_key(password, salt_pwd)
            enc_master_pwd = base64.b64decode(vault_meta['enc_master_pwd'])
            master_key = aes_decrypt(key_pwd, enc_master_pwd)
        except Exception as e:
            messagebox.showerror(_t('error'), _t('lock_failed').format(error=str(e)))
            return
    else:
        master_key = unlocked_master_keys[current_vault]
        del unlocked_master_keys[current_vault]

    try:
        encrypt_plain_back_and_cleanup(vault_root, master_key)
        did_lock = True
    except Exception:
        pass

    save_vault_status(vault_root, False)
    lock_btn.config(state='disabled')
    unlock_btn.config(state='normal', text=_t('unlock'))
    open_btn.config(state='disabled')
    status_lbl.config(text=f"{_t('status')}: {_t('locked')}")

def open_vault():
    global current_vault, unlocked_master_keys
    if not current_vault:
        messagebox.showwarning(_t('error'), _t('not_selected'))
        return
    if current_vault not in unlocked_master_keys:
        messagebox.showwarning(_t('error'), _t('lock_first'))
        return
    try:
        vault_root = Path(app_meta[current_vault])
        plain_dir = vault_root / PLAIN_DIRNAME
        if plain_dir.exists():
            import subprocess
            if sys.platform == 'win32':
                os.startfile(str(plain_dir))
            elif sys.platform == 'darwin':
                subprocess.run(['open', str(plain_dir)])
            else:
                subprocess.run(['xdg-open', str(plain_dir)])
        else:
            pass
    except Exception as e:
        messagebox.showerror(_t('error'), _t('open_failed').format(error=str(e)))


def recover_password():
    global current_vault
    if not current_vault:
        messagebox.showwarning(_t('error'), _t('select_vault'))
        return
    
    try:
        vault_root = Path(app_meta[current_vault])
        vault_meta = load_vault_meta(vault_root)
        if current_vault in unlocked_master_keys:
            master_key = unlocked_master_keys[current_vault]
        else:
            if not vault_meta.get('recovery_enabled', False):
                messagebox.showinfo(_t('info'), _t('no_recovery'))
                return
            def ask_recovery_key():
                win = Toplevel(root)
                win.title(_t('recover'))
                win.transient(root)
                win.grab_set()
                win.resizable(False, False)
                rec_var = StringVar()
                show_rec = BooleanVar(value=False)
                Label(win, text=_t('recovery_key'), font=FONT).grid(row=0, column=0, sticky='w', padx=8, pady=8)
                rec_entry = Entry(win, textvariable=rec_var, show='*', font=FONT, width=32)
                rec_entry.grid(row=0, column=1, padx=8, pady=8)
                rec_eye = Button(win, text='👁', relief='flat', font=FONT, width=2)
                rec_eye.grid(row=0, column=2, padx=2)
                def toggle_rec(event=None):
                    rec_entry.config(show='' if show_rec.get() else '*')
                rec_eye.bind('<ButtonPress-1>', lambda e: show_rec.set(True) or toggle_rec())
                rec_eye.bind('<ButtonRelease-1>', lambda e: show_rec.set(False) or toggle_rec())
                result = {'key': None}
                def ok():
                    val = rec_var.get()
                    if not val:
                        messagebox.showwarning(_t('error'), _t('recovery_empty'), parent=win)
                        return
                    result['key'] = val
                    win.destroy()
                def cancel():
                    win.destroy()
                Button(win, text=_t('ok'), command=ok, bg=BTN_BG, fg=BTN_FG, font=FONT, width=10).grid(row=1, column=1, pady=12)
                Button(win, text=_t('cancel'), command=cancel, font=FONT, width=10).grid(row=1, column=2, pady=12)
                rec_entry.focus_set()
                win.wait_window()
                return result['key']
            recovery_phrase = ask_recovery_key()
            if not recovery_phrase:
                return
            salt_rec = base64.b64decode(vault_meta['salt_rec'])
            key_rec = derive_key(recovery_phrase, salt_rec)
            enc_master_rec = base64.b64decode(vault_meta['enc_master_rec'])
            master_key = aes_decrypt(key_rec, enc_master_rec)

        def ask_new_password():
            win = Toplevel(root)
            win.title(_t('new_password'))
            win.transient(root)
            win.grab_set()
            win.resizable(False, False)
            pw_var = StringVar()
            show_pw = BooleanVar(value=False)
            Label(win, text=_t('enter_new_password'), font=FONT).grid(row=0, column=0, sticky='w', padx=8, pady=8)
            pw_entry = Entry(win, textvariable=pw_var, show='*', font=FONT, width=32)
            pw_entry.grid(row=0, column=1, padx=8, pady=8)
            pw_eye = Button(win, text='👁', relief='flat', font=FONT, width=2)
            pw_eye.grid(row=0, column=2, padx=2)
            def toggle_pw(event=None):
                pw_entry.config(show='' if show_pw.get() else '*')
            pw_eye.bind('<ButtonPress-1>', lambda e: show_pw.set(True) or toggle_pw())
            pw_eye.bind('<ButtonRelease-1>', lambda e: show_pw.set(False) or toggle_pw())
            result = {'pw': None}
            def ok():
                val = pw_var.get()
                if not val:
                    messagebox.showwarning(_t('error'), _t('password_empty'), parent=win)
                    return
                result['pw'] = val
                win.destroy()
            def cancel():
                win.destroy()
            Button(win, text=_t('ok'), command=ok, bg=BTN_BG, fg=BTN_FG, font=FONT, width=10).grid(row=1, column=1, pady=12)
            Button(win, text=_t('cancel'), command=cancel, font=FONT, width=10).grid(row=1, column=2, pady=12)
            pw_entry.focus_set()
            win.wait_window()
            return result['pw']

        new_password = ask_new_password()
        if not new_password:
            return

        salt_pwd = secrets.token_bytes(16)
        key_pwd = derive_key(new_password, salt_pwd)
        enc_master_pwd = aes_encrypt(key_pwd, master_key)

        vault_meta['enc_master_pwd'] = base64.b64encode(enc_master_pwd).decode('ascii')
        vault_meta['salt_pwd'] = base64.b64encode(salt_pwd).decode('ascii')
        update_vault_meta(vault_root, vault_meta)

        messagebox.showinfo(_t('done'), _t('password_updated'))
    except Exception as e:
        messagebox.showerror(_t('error'), _t('recovery_failed').format(error=str(e)))

def import_vault():
    import_dir = filedialog.askdirectory(title=_t('import_vault_dir'), parent=root)
    if not import_dir:
        return
    
    import_path = Path(import_dir)
    
    vault_meta_file = import_path / VAULT_META
    if not vault_meta_file.exists():
        messagebox.showerror(_t('error'), _t('not_valid_vault'))
        return
    
    vault_name = import_path.name
    if vault_name in app_meta:
        messagebox.showerror(_t('error'), _t('vault_exists').format(vault_name=vault_name))
        return
    
    try:
        app_meta[vault_name] = str(import_path)
        save_app_meta(app_meta)
        refresh_vault_list()
        messagebox.showinfo(_t('done'), _t('import_success').format(vault_name=vault_name))
    except Exception as e:
        messagebox.showerror(
            _t('error'),
            _t('import_failed').format(vault_path=import_path, error=str(e))
        )

def delete_vault():
    global current_vault, unlocked_master_keys
    if not current_vault:
        messagebox.showwarning(_t('error'), _t('delete_select'))
        return
    response = messagebox.askyesno(
        _t('confirm'),
        _t('delete_confirm').format(vault_name=current_vault),
        parent=root
    )
    if not response:
        return
    try:
        vault_root = Path(app_meta[current_vault])
        if current_vault in unlocked_master_keys:
            del unlocked_master_keys[current_vault]
        if vault_root.exists():
            shutil.rmtree(vault_root)
        del app_meta[current_vault]
        save_app_meta(app_meta)
        current_vault = None
        refresh_vault_list()
        clear_detail()
        messagebox.showinfo(_t('done'), _t('delete_success').format(vault_name=current_vault))
    except Exception as e:
        messagebox.showerror(_t('error'), _t('delete_failed').format(error=str(e)))

def on_vault_select(event):
    global current_vault
    selection = vault_listbox.curselection()
    if not selection:
        clear_detail()
        return
    
    vault_name = vault_listbox.get(selection[0])
    current_vault = vault_name
    
    if vault_name not in app_meta:
        clear_detail()
        return
    
    vault_root = Path(app_meta[vault_name])
    
    vault_status = load_vault_status(vault_root)
    is_unlocked = vault_status.get("unlocked", False)
    
    vault_meta = load_vault_meta(vault_root)
    description = vault_meta.get('description', '-') if vault_meta else '-'
    info_name.config(text=f"{_t('name')}: {vault_name}")
    info_path.config(text=f"{_t('path')}: {vault_root}")
    info_desc.config(text=f"{_t('desc')}: {description}")
    if is_unlocked:
        unlock_btn.config(state='disabled', text=_t('unlocked'))
        open_btn.config(state='normal')
        lock_btn.config(state='normal')
        recover_btn.config(state='normal')
        status_lbl.config(text=f"{_t('status')}: {_t('unlocked')}")
    else:
        status_lbl.config(text=f"{_t('status')}: {_t('locked')}")
        unlock_btn.config(state='normal', text=_t('unlock'))
        open_btn.config(state='disabled')
        lock_btn.config(state='disabled')
        recover_btn.config(state='normal')

def rename_vault():
    global current_vault, app_meta
    if not current_vault:
        messagebox.showwarning(_t('error'), _t('rename_select'))
        return
    new_name = simpledialog.askstring(_t('rename_title'), _t('rename_prompt').format(vault_name=current_vault), parent=root)
    if not new_name or new_name == current_vault:
        return
    if new_name in app_meta:
        messagebox.showerror(_t('error'), _t('rename_exists'))
        return
    try:
        old_path = Path(app_meta[current_vault])
        new_path = old_path.parent / f"ZLockCore_{new_name}"
        if old_path.exists():
            old_path.rename(new_path)
        app_meta[new_name] = str(new_path)
        del app_meta[current_vault]
        save_app_meta(app_meta)
        current_vault = new_name
        refresh_vault_list()
        clear_detail()
        messagebox.showinfo(_t('done'), _t('rename_success').format(new_name=new_name))
    except Exception as e:
        messagebox.showerror(_t('error'), _t('rename_failed').format(error=str(e)))

btn_new = mkbtn(btn_frame, _t('new_vault'), create_vault_dialog)
btn_new.pack(side=LEFT, padx=2, pady=2)
btn_import = mkbtn(btn_frame, _t('import'), lambda: import_vault())
btn_import.pack(side=LEFT, padx=2, pady=2)
btn_rename = mkbtn(btn_frame, _t('rename'), lambda: rename_vault())
btn_rename.pack(side=LEFT, padx=2, pady=2)
btn_delete = mkbtn(btn_frame, _t('delete'), lambda: delete_vault())
btn_delete.pack(side=LEFT, padx=2, pady=2)


right = Frame(root, bg='white', bd=1, relief='solid')
right.pack(side=LEFT, fill=BOTH, expand=True, padx=(0,12), pady=12)
right_header = Frame(right, bg=ACCENT)
right_header.pack(fill=X)
right_label = Label(right_header, text=_t('details'), bg=ACCENT, fg='white', font=('Segoe UI', 12, 'bold'))
right_label.pack(side=LEFT, padx=8, pady=8)
detail_frame = Frame(right, bg='white')
detail_frame.pack(fill=BOTH, expand=True, padx=12, pady=12)

info_name = Label(detail_frame, text=f"{_t('name')}: —", bg='white', anchor='w', font=('Segoe UI',11,'bold'))
info_name.pack(fill=X)
info_desc = Label(detail_frame, text=f"{_t('desc')}: ", bg='white', anchor='w')
info_desc.pack(fill=X, pady=(4,0))
info_path = Label(detail_frame, text=f"{_t('path')}: ", bg='white', anchor='w')
info_path.pack(fill=X, pady=(4,10))
status_lbl = Label(detail_frame, text=f"{_t('status')}: -", bg='white', anchor='w')
status_lbl.pack(fill=X, pady=(4,10))

btns = Frame(detail_frame, bg='white')
btns.pack(pady=8)
unlock_btn = mkbtn(btns, _t('unlock'), lambda: unlock_vault())
open_btn = mkbtn(btns, _t('open'), lambda: open_vault())
lock_btn = mkbtn(btns, _t('lock'), lambda: lock_vault())
recover_btn = mkbtn(btns, _t('recover'), lambda: recover_password())
unlock_btn.pack(side=LEFT, padx=6, pady=4)
open_btn.pack(side=LEFT, padx=6, pady=4)
lock_btn.pack(side=LEFT, padx=6, pady=4)
recover_btn.pack(side=LEFT, padx=6, pady=4)

current_vault = None
unlocked_master_keys = {}


def refresh_vault_list():
    vault_listbox.delete(0, END)
    for name in app_meta.keys():
        vault_listbox.insert(END, name)


def clear_detail():
    global current_vault
    current_vault = None
    info_name.config(text=f"{_t('name')}: —")
    info_desc.config(text=f"{_t('desc')}: ")
    info_path.config(text=f"{_t('path')}: ")
    status_lbl.config(text=f"{_t('status')}: -")
    unlock_btn.config(state='normal', text=_t('unlock'))
    open_btn.config(state='disabled')
    lock_btn.config(state='disabled')
    recover_btn.config(state='disabled')

vault_listbox.bind('<<ListboxSelect>>', lambda e: on_vault_select(e) if vault_listbox.curselection() else None)


refresh_vault_list()
clear_detail()
_refresh_ui_texts()
def show_meta_path_label():
    pass

root.mainloop()
