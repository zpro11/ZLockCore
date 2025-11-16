# ZLockCore — Vault Manager

ZLockCore is a graphical file vault manager application for Windows, protected by a password and an optional recovery key. The program allows you to create encrypted vaults, securely store files, and unlock, lock, import, rename, and delete vaults.

## Main Features
- Manage multiple vaults, each in a separate folder
- Encrypt and decrypt files using the AES-GCM algorithm
- Password and recovery key (word list) protection
- Add and restore files, import/export vaults
- Password reset with recovery key
- Modern, Hungarian-language graphical interface (Tkinter)
- Executable .exe file created with PyInstaller

## Creating the exe manually
```sh
   pip install pyinstaller
   ```

```sh
   pyinstaller --clean --onedir --noconsole --noupx --icon=icon.ico main.py
   ```
## Installation and Running

Find the latest version of the program at: https://github.com/zpro11/ZLockCore/releases For Windows, download the ZLockCore_installer.exe for a standard system-wide installation, or the ZLockCore_executable.zip file. (For Linux, use the ZLockCore_executable_LINUX.zip file.) For the installer, follow the on-screen instructions. For the ZIP, extract its contents to a folder and run the executable binary.

# Running main.py:

1. **Python 3.8+ required**
2. Install the required packages:
   ```sh
   pip install cryptography
   ```
3. Run the program:
   ```sh
   python main.py
   ```

## Usage
1. **Create a new vault**
   - Click the "New Vault" button
   - Enter a name, choose a folder, set a password
   - (Recommended) Generate a recovery key: write it down or save it in a secure place!
2. **Unlock a vault**
   - Select the vault, then click the "Unlock" button and enter the password
3. **Add files**
   - With the vault unlocked, click the "Add Files" button and select the files
4. **Lock the vault**
   - Click the "Lock" button. The files will be encrypted again
5. **Open the vault**
   - With the vault unlocked, click the "Show Vault" button
6. **Reset password**
   - "Reset Password" button: after entering the recovery key, a new password can be set
7. **Import/rename/delete vault**
   - In the list on the left, select the vault and then the appropriate button

## File Structure
- Each vault is located in a separate folder
- Encrypted files: in the `storage/` folder, with `.cbox` extension
- Decrypted files: in the `plain/` folder (only after unlocking)
- Metadata: `vault.meta.json`, `vault_status.json`

## License
See: LICENSE.txt
BY INSTALLING AND USING THE PROGRAM, YOU ACCEPT THE LICENSE AGREEMENT.

## Developer Information
- Main file: `main.py`
- Encryption: Scrypt KDF + AES-GCM
- GUI: Tkinter

## Multilingual Support (Language Selection)

The program supports multiple languages. By default, you can choose between English and Hungarian.

You can select the language under the "Language" menu in the top right corner. The selected language will be saved and remembered after restarting the program.

### Adding Your Own or More Languages

If you want to add/use more languages, download the `more_languages.json` file and place this extension in the folder where `main.py` or `ZLockCore.exe` is located. (On Linux, place it in the folder containing the executable binary.) (The ZLockCore_installer automatically installs the more_languages.json file into the program folder.)

If this file is present, the program will automatically offer the languages listed in it in the menu. If not, only the default English and Hungarian will be available.

---

**Created by Zoárd Gódor, developer of ZLockCore**
