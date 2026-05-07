import os
import sys
import json
from dotenv import load_dotenv
from anyrun_client import AnyRunClient, AnyRunAPIError

def fetch_and_save(uuid: str, output_var_name: str):
    load_dotenv()
    api_key = os.getenv("ANYRUN_API_KEY")
    
    if not api_key:
        print("[-] Lỗi: Không tìm thấy ANYRUN_API_KEY trong file .env")
        sys.exit(1)

    print(f"[*] Đang khởi tạo kết nối Any.Run API...")
    client = AnyRunClient(api_key=api_key)
    
    try:
        print(f"[*] Đang lấy dữ liệu Summary Report cho task: {uuid}...")
        report_json = client.get_task_report(uuid)
        
        print(f"[*] Đang lấy dữ liệu IOC cho task: {uuid}...")
        ioc_json = client.get_task_iocs(uuid)
        
        # Ghi ra file python format
        out_file = f"demo_data_{output_var_name.lower()}.py"
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(f'"""\nData fetched from public task: {uuid}\n"""\n\n')
            f.write(f"{output_var_name}_REPORT = ")
            f.write(json.dumps(report_json, indent=4, ensure_ascii=False))
            f.write("\n\n")
            f.write(f"{output_var_name}_IOC = ")
            f.write(json.dumps(ioc_json, indent=4, ensure_ascii=False))
            f.write("\n")
            
        print(f"[+] Thành công! Dữ liệu đã được lưu vào {out_file}.")
        print(f"[*] Bạn có thể copy nội dung file này dán vào demo_data.py để làm mẫu demo mới.")
        
    except AnyRunAPIError as e:
        print(f"[-] Lỗi API: {e}")
    except Exception as e:
        print(f"[-] Lỗi không xác định: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Sử dụng: python fetch_public_demo.py <UUID> <VAR_NAME>")
        print("Ví dụ: python fetch_public_demo.py 550e8400-e29b-41d4-a716-446655440000 RANSOMWARE")
        sys.exit(1)
        
    task_uuid = sys.argv[1]
    var_name = sys.argv[2]
    fetch_and_save(task_uuid, var_name)
