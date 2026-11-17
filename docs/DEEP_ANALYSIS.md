# Phân tích sâu báo cáo Any.Run

Trong **Bằng chứng nguồn → Phân tích sâu**, mở từng nhóm khi cần: chuỗi tiến trình, tệp thả ra khớp tiến trình, metadata PE/DLL và đối chiếu đặc trưng họ. Hồ sơ cũ cần phân tích lại vì phiên bản pipeline và khóa cache đã đổi.

## Nguồn và mức bằng chứng

- `observed`: dữ kiện sandbox cung cấp, ví dụ DLL được nạp hay cạnh UUID. Không xác nhận endpoint thật bị nhiễm.
- `signature`: chữ ký hành vi hoặc nhận diện TrID do nguồn báo cáo.
- `inference`: suy luận từ dữ kiện; có mức tin cậy `high/medium/low` và dẫn chứng.
- `family_reference`: tham chiếu ATT&CK về họ mã độc; không phải sự kiện trong hồ sơ.

`report_context.py` chỉ phân tích XML để đọc cạnh văn bản `NODE_UUID → NODE_UUID`; không chèn SVG vào giao diện, không tải tài nguyên SVG và từ chối DTD/entity. Chỉ dùng UUID duy nhất có trong danh sách tiến trình; bỏ cạnh dashed/annotated, nhiều cha, tự tham chiếu và vòng lặp. Nếu nguồn không có cạnh đọc được, quan hệ theo tên duy nhất vẫn gắn nhãn suy luận. PID lặp không được dùng để gán artifact.

`deep_analysis.py` gắn tệp/registry/kết nối/chữ ký vào tiến trình theo PID duy nhất hoặc UUID. Khớp đường dẫn Windows không phân biệt hoa thường; không mở rộng biến môi trường của máy phân tích. Tệp thả khớp đường dẫn chạy là một liên hệ, chưa chứng minh thả trước hay chạy ngay. Chỉ so sánh thời gian khi cả hai mốc nguồn tồn tại; mốc mâu thuẫn được ghi riêng.

Lệnh được xử lý bằng quy tắc: bỏ caret escape, gộp chuỗi literal, giải mã PowerShell UTF-16LE base64, trích URL/IP/đường dẫn. Không chạy shell, `eval` hay biểu thức trong báo cáo. LOLBin chỉ được ánh xạ khi có tham số hành vi tương ứng; tên công cụ hoặc `//nologo` đơn lẻ không đủ. Chỉ báo trích từ lệnh là ứng viên cần xác minh, không tự vào blocklist.

Tên Unicode riêng lẻ là tín hiệu yếu, không tự ánh xạ T1036. `exploer.exe`, tên hệ thống sai vị trí và `System.exe` trong Startup là ứng viên ngụy trang. Vai trò dropper/loader/payload/persistence đều là giả thuyết. Cờ injection chỉ được giữ khi nguồn cung cấp boolean.

## PE và DLL

Timestamp PE so với **thời điểm phân tích nguồn**, không so với đồng hồ lúc chạy lại. Timestamp tương lai không tự chứng minh timestomping. Thiếu dữ liệu chữ ký không có nghĩa unsigned; trạng thái chữ ký rõ ràng chỉ được hiển thị là nguồn báo cáo, chưa kiểm tra Authenticode.

Nạp `mscoree.dll`/`clr.dll`/`coreclr.dll` ghi nhận thành phần runtime .NET của đúng tiến trình, không kết luận cả tệp ZIP chính là .NET hay tệp đó độc hại. Gợi ý ILSpy/dnSpy để kiểm tra assembly. TrID là nhận diện xác suất.

`vaultcli.dll`, `dpapi.dll`, `rstrtmgr.dll`, `samlib.dll` chỉ sinh suy luận năng lực yếu; không kết luận đánh cắp mật khẩu hay mã hóa. DLL phổ biến như advapi32/bcrypt không sinh cảnh báo năng lực. Các dữ kiện metadata/module là evidence, không trở thành IOC chặn.

## Bằng chứng mức mã lệnh (assembly)

Trong **Ghidra trên máy**, khi một hồ sơ sandbox đang mở, kết quả phân tích mẫu được lưu cùng hồ sơ đó. `MalwareSummaryExporter.java` duyệt mọi lệnh `CALL`, lần theo thunk và con trỏ IAT tới hàm import, rồi xuất 10 lệnh trước và 3 lệnh sau mỗi lệnh gọi (địa chỉ, byte, mnemonic, chuỗi hoặc API mà toán hạng trỏ tới). Tối đa 3 vị trí cho mỗi API, 60 vị trí cho mỗi mẫu; số lệnh gọi thật vẫn được đếm đủ.

`code_evidence.py` gom các vị trí gọi theo hành vi (`BEHAVIOR_APIS`), dùng chung ID với nhóm tác động của `impact_analysis.py`. Bản xuất Markdown/HTML/PDF in listing và ghi rõ từng hành vi **khớp** nhóm tác động sandbox đã quan sát hay chỉ là năng lực có trong mã. Listing chứng minh mã có trong tệp, không chứng minh mã đã chạy. Nếu hash của mẫu không có trong hồ sơ, báo cáo in cảnh báo thay vì ngầm coi là cùng một tệp.

Giới hạn: mẫu bị pack chỉ lộ đoạn giải nén; mẫu .NET không có lệnh gọi import dạng này (dùng ILSpy/dnSpy); API gọi qua địa chỉ tính lúc chạy không được nhận ra. Khi đó kết quả ghi rõ là không tìm thấy, không coi là sạch.

### Phân tích mẫu thật trong máy ảo

Để có assembly của chính mẫu mã độc mà không để tệp `.exe` chạm máy thật, phân tích trong máy ảo cô lập rồi chỉ mang file JSON kết quả ra:

1. Trong VM (snapshot, tắt mạng, không shared folder): `python start.py` chuẩn bị Ghidra/JDK, rồi `python -m ir_workspace.cli.analyze_sample "mau.exe" -o result.json`. `analyze_sample.py` gọi đúng `analyze_sample()` và ghi ra JSON gồm triage, summary và các vị trí gọi — chỉ metadata và văn bản disassembly, không có mã thực thi.
2. Chép `result.json` ra máy thật. Trong tab **Ghidra trên máy → Nhập kết quả từ máy ảo**, chọn file khi hồ sơ sandbox tương ứng đang mở. `/api/ghidra/import` làm sạch JSON không tin cậy (chỉ đọc trường đã biết, giới hạn kích thước, dựng lại `code_evidence` từ summary ở phía server), đối chiếu SHA256 với hồ sơ rồi lưu kèm.

Vì mẫu thật khớp hash hồ sơ, cảnh báo hash biến mất và đoạn assembly là của chính con mã độc. Mẫu không bao giờ chạy hay nằm trên máy thật; thứ ra khỏi VM chỉ là JSON.

## Đối chiếu họ và agent

`data/family_expectations.json` chứa tập `uses` cho WannaCry S0366, Emotet S0367 và RedLine Stealer S1240, trích từ STIX Enterprise ATT&CK 19.2. URL, SHA256 nguồn và relationship ID được lưu cùng dữ liệu. Khi chạy phân tích không cần Internet để tải danh mục.

Ba nhóm: khớp **ứng viên** trong hồ sơ; chưa quan sát; ngoài tập tham chiếu. Không suy đoán nguyên nhân thiếu quan sát (như sandbox cách ly) hay khẳng định biến thể mới chỉ vì khác danh mục.

Agent có thêm `get_process_story` (phân trang), `get_family_expectations`, `get_static_profile`. Công cụ trả cả phân tích và một số source row; ID không có trong source row trả về phải được đọc thêm bằng `get_evidence`. Kết quả `attack_narrative` gồm từng câu, mức bằng chứng và evidence ID; câu có ID lạ hoặc chưa đọc bị bỏ, không đưa vào kết quả. Chế độ quy tắc có diễn biến theo nguồn và vẫn ghi rõ `rule_based`, không gọi là kết quả LLM.

Kiểm tra với DeepSeek thật trên hai báo cáo (30/10/2026): agent điều tra hoàn thành ở chế độ `llm` trong khoảng 26–28 giây.
Để giữ dưới giới hạn 60 giây và không đốt lượt vào việc nộp lại:

- `attack_narrative` không bắt buộc, tối đa 6 câu. Câu dẫn evidence chưa đọc hoặc không tồn tại bị bỏ (đếm ở `narrative_dropped`), không làm hỏng cả assessment.
- Mã ATT&CK được đối chiếu danh mục: ID bị thu hồi được thay nếu ID mới đúng tactic (ví dụ T1562.001 → T1685), ID sai tactic hoặc không có bị bỏ. Mọi chỉnh sửa ghi ở `mitre_corrections` và hiện trên giao diện.
- Hạn chót chung cho một lượt phân tích (`PIPELINE_DEADLINE_SECONDS`, tính từ lúc bắt đầu pipeline: mặc định 45 giây trên Vercel, 110 giây khi chạy trên máy) áp cho cả agent điều tra và agent IOC chạy song song. Timeout của **từng lần gọi AI** bị giới hạn bởi thời gian còn lại; không thử lại (429/5xx) nếu thời gian chờ vượt hạn chót. Agent điều tra được nhắc nộp khi còn khoảng 12 giây. Hết hạn thì phần đó dùng quy tắc (`fallback`/`partial`).
- Trong chuỗi hành vi, phần ảnh hưởng và quyết định khuyến nghị, mã evidence agent dẫn nhưng chưa đọc bị lược; nhận định cần ít nhất một nguồn đã đọc, nếu không vẫn bị từ chối. Tổng số mã bị lược ghi ở `citations_dropped` và hiện trên giao diện; nên báo cáo chỉ số này trong thực nghiệm. Khi chạy thực nghiệm, ghi lại `PIPELINE_DEADLINE_SECONDS` vì thời gian cho phép ảnh hưởng tỷ lệ hoàn thành bằng AI.
- Chỉ các DLL có ý nghĩa phân tích (`NOTABLE_MODULES` trong `report_context.py`) được giữ làm evidence; các DLL còn lại chỉ đếm (`moduleCount`). Hồ sơ WannaCry thật giảm từ 5,88 MB xuống 4,33 MB, dưới giới hạn response 4,5 MB của Vercel.

JSON giữ toàn bộ cấu trúc; Markdown/HTML/PDF có phần diễn biến và phân tích sâu. Không thay verdict nguồn và không tự thực thi khắc phục.

Chữ ký YARA về năng lực chụp màn hình chỉ là ứng viên T1113, chưa chứng minh đã chụp màn hình. Chữ ký nguồn về chứng thư không tin cậy được ghi riêng với trạng thái `signature`, không biến thành xác minh chữ ký số độc lập. Evidence bị cắt khỏi kết quả công cụ do giới hạn ngữ cảnh không được tính là agent đã đọc.
