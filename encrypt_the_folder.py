import os
import sys
import base64
import hashlib
import time
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from tqdm import tqdm
import winreg

# ======================
# === 設定參數 ========
# ======================
CHUNK_SIZE = 64 * 1024
MAGIC_HEADER = b"tsauv1"
DELETE_AFTER_DECRYPT = True  # True=解密後刪除原檔案，False=保留原檔
REG_PATH = r"Software\TsauEncrypt"

# ======================
# === 登錄檔操作 =======
# ======================
def save_last_folder(path: Path):
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_PATH) as key:
            winreg.SetValueEx(key, "LastFolder", 0, winreg.REG_SZ, str(path))
    except Exception as e:
        print(f"[!] 無法寫入登錄檔: {e}")

def load_last_folder() -> Path | None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, "LastFolder")
            p = Path(val)
            if p.exists() and p.is_dir():
                return p
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"[!] 讀取登錄檔錯誤: {e}")
    return None

# ======================
# === 密碼與金鑰處理 ==
# ======================
def derive_key(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()

def get_keyid(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()[:8]

# ======================
# === 檔名加解密 =======
# ======================
def encrypt_name(name: str, password: str) -> str:
    key = derive_key(password)
    cipher = AES.new(key, AES.MODE_CBC)
    ct = cipher.encrypt(pad(name.encode(), AES.block_size))
    return base64.urlsafe_b64encode(cipher.iv + ct).decode().rstrip("=")

def decrypt_name(enc_name: str, passwords: list[str]) -> str | None:
    padded = enc_name + "=" * (-len(enc_name) % 4)
    try:
        data = base64.urlsafe_b64decode(padded.encode())
    except Exception:
        return None
    iv, ct = data[:16], data[16:]
    for password in passwords:
        key = derive_key(password)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        try:
            return unpad(cipher.decrypt(ct), AES.block_size).decode()
        except Exception:
            continue
    return None

# ======================
# === 檔案加密 ========
# ======================
def encrypt_file(infile: Path, outfile: Path, password: str):
    try:
        # 檢查是否已加密
        with open(infile, "rb") as fin:
            if fin.read(len(MAGIC_HEADER)) == MAGIC_HEADER:
                print(f"[!] 跳過 {infile}: 已加密過")
                return

        key = derive_key(password)
        keyid = get_keyid(password)
        cipher = AES.new(key, AES.MODE_CBC)
        filesize = infile.stat().st_size

        with open(infile, "rb") as fin, open(outfile, "wb") as fout, tqdm(
            total=filesize, unit="B", unit_scale=True, desc=f"加密 {infile.name}"
        ) as pbar:
            fout.write(MAGIC_HEADER)
            fout.write(keyid)
            fout.write(cipher.iv)
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break
                if len(chunk) < CHUNK_SIZE:
                    chunk = pad(chunk, AES.block_size)
                    fout.write(cipher.encrypt(chunk))
                    pbar.update(len(chunk))
                    break
                fout.write(cipher.encrypt(chunk))
                pbar.update(len(chunk))

        # 簡單的檔案刪除，遇到錯誤時重試一次
        try:
            os.remove(infile)
            print(f"[+] 加密完成: {infile} -> {outfile}")
        except PermissionError:
            time.sleep(0.1)  # 短暫等待
            try:
                os.remove(infile)
                print(f"[+] 加密完成: {infile} -> {outfile}")
            except Exception as e:
                print(f"[+] 加密完成: {infile} -> {outfile} (無法刪除原檔案: {e})")
        except Exception as e:
            print(f"[+] 加密完成: {infile} -> {outfile} (無法刪除原檔案: {e})")
            
    except Exception as e:
        print(f"[!] 加密失敗 {infile}: {e}")

# ======================
# === 檔案解密 ========
# ======================
def decrypt_file(infile: Path, outfile: Path, passwords: list[str]) -> bool:
    try:
        with open(infile, "rb") as fin:
            header = fin.read(len(MAGIC_HEADER))
            if header != MAGIC_HEADER:
                print(f"[!] 跳過 {infile}: 非合法加密檔案")
                return False

            file_keyid = fin.read(8)
            iv = fin.read(16)

            for password in passwords:
                key = derive_key(password)
                keyid = get_keyid(password)
                if keyid != file_keyid:
                    continue

                cipher = AES.new(key, AES.MODE_CBC, iv)
                filesize = infile.stat().st_size - len(MAGIC_HEADER) - 8 - 16

                with open(outfile, "wb") as fout, tqdm(
                    total=filesize, unit="B", unit_scale=True, desc=f"解密 {infile.name} (key={password})"
                ) as pbar:
                    next_chunk = b""
                    while True:
                        chunk = fin.read(CHUNK_SIZE)
                        if len(chunk) == 0:
                            if next_chunk:
                                fout.write(unpad(cipher.decrypt(next_chunk), AES.block_size))
                                pbar.update(len(next_chunk))
                            break
                        if next_chunk:
                            fout.write(cipher.decrypt(next_chunk))
                            pbar.update(len(next_chunk))
                        next_chunk = chunk

                # 明確關閉檔案（關鍵步驟）
                fin.close()
                
                if DELETE_AFTER_DECRYPT:
                    try:
                        os.remove(infile)
                        print(f"[+] 解密完成並刪除: {infile} -> {outfile} (使用密碼 {password})")
                    except PermissionError:
                        time.sleep(0.1)  # 短暫等待
                        try:
                            os.remove(infile)
                            print(f"[+] 解密完成並刪除: {infile} -> {outfile} (使用密碼 {password})")
                        except Exception:
                            print(f"[+] 解密完成: {infile} -> {outfile} (使用密碼 {password})，無法刪除原檔案")
                    except Exception:
                        print(f"[+] 解密完成: {infile} -> {outfile} (使用密碼 {password})，無法刪除原檔案")
                else:
                    print(f"[+] 解密完成: {infile} -> {outfile} (使用密碼 {password})，原檔案保留")

                return True

            print(f"[!] 跳過 {infile}: 無對應密碼")
            return False
            
    except Exception as e:
        print(f"[!] 解密失敗 {infile}: {e}")
        return False

# ======================
# === 資料夾遞迴加密 ==
# ======================
def encrypt_folder(folder: Path, password: str):
    items = list(folder.iterdir())
    
    # 先加密檔案
    for item in items:
        if item.is_file():
            new_name = encrypt_name(item.name, password) + ".ecp"
            encrypt_file(item, item.parent / new_name, password)
    
    # 再處理子資料夾
    for item in items:
        if item.is_dir() and item.exists():
            encrypt_folder(item, password)
            new_name = encrypt_name(item.name, password)
            try:
                item.rename(item.parent / new_name)
                print(f"[+] 加密資料夾: {item} -> {new_name}")
            except Exception as e:
                print(f"[!] 加密資料夾失敗 {item}: {e}")

# ======================
# === 資料夾遞迴解密 ==
# ======================
def decrypt_folder(folder: Path, passwords: list[str], failed_files=None) -> list[str]:
    if failed_files is None:
        failed_files = []

    items = list(folder.iterdir())
    
    # 先解密檔案
    for item in items:
        if item.is_file() and item.suffix == ".ecp":
            original_name = decrypt_name(item.stem, passwords)
            if original_name:
                success = decrypt_file(item, item.parent / original_name, passwords)
                if not success:
                    failed_files.append(str(item))
            else:
                print(f"[!] 檔名解密失敗 {item}")
                failed_files.append(str(item))
    
    # 再處理子資料夾
    for item in items:
        if item.is_dir() and item.exists():
            decrypt_folder(item, passwords, failed_files)
            original_name = decrypt_name(item.name, passwords)
            if original_name:
                try:
                    item.rename(item.parent / original_name)
                    print(f"[+] 解密資料夾: {item} -> {original_name}")
                except Exception as e:
                    print(f"[!] 解密資料夾失敗 {item}: {e}")
                    failed_files.append(str(item))
            else:
                failed_files.append(str(item))

    return failed_files

# ======================
# === 主程式入口 =======
# ======================
if __name__ == "__main__":
    last_folder = load_last_folder()
    if last_folder:
        print(f"[i] 找到上次加/解密的資料夾: {last_folder}")

    mode = input("選擇模式 (e=加密 / d=解密 / s=修改資料夾): ").strip().lower()
    folder = last_folder

    if mode == "e":
        if not folder or not folder.exists() or not folder.is_dir():
            print("錯誤: 資料夾不存在！")
            sys.exit(1)

        save_last_folder(folder)
        password = input("輸入密鑰 (只能一組): ").strip()
        if not password:
            print("錯誤: 必須輸入一組密碼！")
            sys.exit(1)

        print(f"[i] 開始加密資料夾: {folder}")
        encrypt_folder(folder, password)
        print(f"[i] 加密完成")

    elif mode == "d":
        if not folder or not folder.exists() or not folder.is_dir():
            print("錯誤: 資料夾不存在！")
            sys.exit(1)

        password_input = input("輸入密鑰 (可多組，用逗號分隔): ").strip()
        passwords = [p.strip() for p in password_input.split(",") if p.strip()]
        if not passwords:
            print("錯誤: 至少要輸入一組密碼！")
            sys.exit(1)

        print(f"[i] 開始解密資料夾: {folder}")
        failed = decrypt_folder(folder, passwords)
        if failed:
            print("\n=== 以下檔案/資料夾解密失敗，需要提供對應密碼 ===")
            for f in failed:
                print(f" - {f}")
        else:
            print("\n所有檔案解密成功！")

        save_last_folder(folder)

    elif mode == "s":
        while True:
            folder_input = input("請輸入更新的資料夾路徑: ").strip()
            folder = Path(folder_input)
            if not folder.exists() or not folder.is_dir():
                print("錯誤: 資料夾不存在！")
                continue
            save_last_folder(folder)
            print(f"[i] 已更新預設資料夾為: {folder}")
            break

    else:
        print("錯誤: 未知的模式")