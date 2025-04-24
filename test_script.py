from lightweight_antivirus import LightweightAntivirus

antivirus = LightweightAntivirus()

hash_val = antivirus.calculate_file_hash("test_files/trojan.exe")
antivirus.add_signature(hash_val, "Trojan.Win32", "Detected via known malware signature.")


results = antivirus.scan_directory("test_files")


for threat in results:
    print(f"[DETECTED] {threat['type'].upper()} - {threat['name']} in {threat['file_path']}")
    print(f"Description: {threat['description']}\n")
