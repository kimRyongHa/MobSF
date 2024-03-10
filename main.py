# main.py
import os
import shutil
import subprocess
from collections import Counter
import math
from Crypto.Cipher import AES
from io import BytesIO
from Crypto.Util.Padding import unpad
import api  # api.py에서 정의된 함수들을 임포트
import time

FILE = ''

def calculate_file_entropy(file_path):
    with open(file_path, 'rb') as f:
        byte_arr = list(f.read())
    filesize = len(byte_arr)
    frequencies = Counter(byte_arr)
    entropy = 0
    for byte, freq in frequencies.items():
        p_x = freq / filesize
        entropy += -p_x * math.log2(p_x)
    return entropy

def find_dex_files_needing_decryption(directory, entropy_threshold=7.5):
    files_needing_decryption = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".dex"):
                file_path = os.path.join(root, file)
                entropy = calculate_file_entropy(file_path)
                if entropy > entropy_threshold:
                    files_needing_decryption.append(file_path)
    return files_needing_decryption

def decrypt_dex_files(file_paths, key=b'dbcdcfghijklmaop'):
    print(file_paths)
    key_bytes = key
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    for file_path in file_paths:
        with open(file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        dex_memory = BytesIO(decrypted_data)
        decrypted_file_path = file_path.replace('.dex', '_decrypted.dex')
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(dex_memory.getvalue())
        os.remove(file_path)

def depack_apk(apk_file_path, output_dir):
    command = [
        'apktool.bat',
        "--match-original",
        "-f",
        "-s",
        "d",
        apk_file_path,  # 디패키징할 APK 파일의 경로
        "-o",
        output_dir      # 디패키징된 파일을 저장할 경로
    ]
    subprocess.check_call(command)

def repack_apk(input_dir, apk_file_path):
    command = ['apktool.bat', 'b', input_dir, '-o', apk_file_path]
    subprocess.check_call(command)

def process_inner_apks(directory, original_apk_path):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.apk') and not file.endswith('_repacked.apk'):
                inner_apk_path = os.path.join(root, file)
                inner_output_dir = inner_apk_path + "_depackaged"
                inner_repacked_apk_path = inner_apk_path.replace('.apk', '_repacked.apk')
                depack_apk(inner_apk_path, inner_output_dir)
                dex_files = find_dex_files_needing_decryption(inner_output_dir)
                decrypt_dex_files(dex_files)
                repack_apk(inner_output_dir, inner_repacked_apk_path)
                os.remove(inner_apk_path)  # 원본 내부 APK 삭제
                shutil.move(inner_repacked_apk_path, inner_apk_path)  # 리패키징된 내부 APK를 원래 위치로 이동
                shutil.rmtree(inner_output_dir)  # 디패키징된 내부 APK 디렉토리 삭제

def process_apk(apk_file_path):
    global FILE
    output_dir = apk_file_path + "_depackaged"
    depack_apk(apk_file_path, output_dir)
    dex_files_needing_decryption = find_dex_files_needing_decryption(output_dir)
    decrypt_dex_files(dex_files_needing_decryption)
    process_inner_apks(output_dir, os.path.dirname(apk_file_path))
    repacked_apk_path = apk_file_path.replace('.apk', '_repacked.apk')
    FILE=repacked_apk_path
    repack_apk(output_dir, repacked_apk_path)
    shutil.rmtree(output_dir)  # 디패키징된 외부 APK 디렉토리 삭제, 리패키징된 APK는 유지
    

def touch_process() :
    time.sleep(20)

    api.touch(380, 1000)

    time.sleep(3)
    api.touch(680, 400)
    time.sleep(1)
    api.touch(50, 100)
    time.sleep(3)
    api.touch(380, 1000)
    time.sleep(3)
    api.touch(380,920)


def Static_analysis(apk_file_path):
    process_apk(apk_file_path)

    # 정적 분석 실행
    upload_response = api.upload(FILE)  # 수정된 upload 함수 호출
    if upload_response is None:
        print("Failed to upload APK for analysis.")
        return

    scan_response = api.scan(upload_response.text)
    if scan_response is None:
        print("Failed to scan APK for analysis.")
        return
    
    hash_value = scan_response.json().get('md5')
    if not hash_value:
        print("Failed to get hash from scan response.")
        return
    
    api.pdf(hash_value)
    api.delete(hash_value)

def Dynamic_analysis(apk_file_path) :
    up = api.upload(apk_file_path)

    scan_result = api.scan(up.text)
    scan_hash = scan_result.json()['md5']

    setting = api.dynamic_analysis_setting(scan_hash)
    activitiy_list = setting['activities']

    frida_path = 'frida_script.js'
    try:
        with open(frida_path, 'r') as file:
            frida_code = file.read()
    except Exception as e:
        print(f"Error reading the Frida script: {e}")

    try:
        api.frida_instrument(scan_hash, default_hooks=True, frida_code=frida_code)
        print("Performing Frida Instrumentation")
    except Exception as e:
        print(f"An error occurred: {e}")
        print("Please check Frida Code")

    touch_process()

    api.dynamic_analysis_activity_test(scan_hash, activitiy_list)

    return

def main():
    global FILE

    select_analysis = input('Choose analysis type (Static/Dynamic)[S/D] : ')
    file_path = input("Enter the path of your APK file: ")
    apk_file_path = file_path.replace("\\", "\\\\")

    # C:\Users\user\Downloads\sample\sample.apk
    FILE = apk_file_path  # FILE 전역 변수 설정
    
    if select_analysis == 'S' :
        Static_analysis(apk_file_path)

    elif select_analysis == 'D' :
        Dynamic_analysis(apk_file_path)
        return



if __name__ == "__main__":
    main()
