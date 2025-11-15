# ZLockCore — Vault Manager

ZLockCore is a graphical file vault manager application for Windows, protected by a password and an optional recovery key. The program allows you to create encrypted vaults, securely store files, and unlock, lock, import, rename, and delete vaults.

## Main features

- Manage multiple safes, each in a separate folder
# ZLockCore — Vault Manager

ZLockCore is a graphical file vault manager application for Windows, protected by a password and an optional recovery key. The program allows you to create encrypted vaults, securely store files, and unlock, lock, import, rename, and delete vaults.

## Main features

- Manage multiple safes, each in a separate folder
- Encrypt and decrypt files using the AES-GCM algorithm
- Password and recovery key (key list) protection
- Add and restore files, import/export safes
- Recover passwords with a recovery key
- Modern, Hungarian-language graphical interface (Tkinter)
- Executable .exe file created with Pyinstaller.

## Manual creation of the exe

```sh
pip install pyinstaller
```

```sh
pyinstaller --clean --onefile --noconsole --noupx --icon=icon.ico main.py
```

## Running

1. **Python 3.8+ required**
2. Install the necessary packages:

```sh
pip install cryptography
```

3. Run the program:

```sh
python main.py
```

Or simply run ZLockCore.exe or ZLockCore_installer.exe

## Usage

1. **Creating a new safe**
   - Click on the "New Safe" button
   - Give it a name, select a folder, set a password
   - (Recommended) Generate a recovery key: write it down or save it in a safe place!

2. **Unlocking a safe**
   - Select the safe, then click on the "Unlock" button and enter the password

3. **Adding files**
   - For an unlocked safe, click the "Add files" button and select the files

4. **Lock safe**
   - Click the "Lock" button. The files will be encrypted again

5. **Open safe**
   - For an unlocked safe, click on the "Show safe" button

6. **Resetting the password**
   - Click on the "Reset password" button, enter the recovery key, and set a new password

7. **Importing/renaming/deleting a safe**
   - Select the vault from the list on the left, then click the appropriate button

## File structure

- Each vault is located in a separate folder
- Encrypted files: in the `storage/` folder, with the `.cbox` extension
- Decrypted files: in the `plain/` folder (only after decryption)
- Metadata: `vault.meta.json`, `vault_status.json`

## Security tips

- Always save your recovery key in a safe place!
- Do not share the vault folder or store it in a public place!
- The program cannot restore your password without the recovery key!

## License

See: LICENSE.txt

## Developer information

- Main file: `main.py`
- Encryption: Scrypt KDF + AES-GCM
- GUI: Tkinter

## Multilingualism (language selection)

The program supports multiple languages. By default, you can choose between English and Hungarian.

You can select the language in the "Language" menu in the upper right corner. The selected language is saved and remembered even after restarting the program.

### Adding your own or additional languages

If you want to add/use additional languages, download the file named `more_languages.json` and place it in the folder where `main.py` or `ZLockCore.exe` is located. (ZLockCore_installer automatically installs the more_languages.json file in the program folder)

If this file is present, the program will automatically offer the languages it contains in the menu. If it is not present, you can only choose between the default English and Hungarian.

---

**Created by: Zoárd Gódor, developer of ZLockCore**
