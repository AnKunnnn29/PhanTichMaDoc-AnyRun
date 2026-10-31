"""Human-reviewed response steps. Sandbox observations are not endpoint findings."""

PROFILES = {
 'triage': {
  'goal':'Xác định máy và thời điểm thực sự liên quan trước khi can thiệp.',
  'steps':['Ghi nhận nguồn báo cáo, SHA256 mẫu và thời gian phân tích; đánh dấu dữ liệu mô phỏng nếu là demo.',
           'Tìm SHA256, tiến trình hoặc IOC trong EDR/SIEM; ghi rõ hostname, tài khoản và mốc thời gian của kết quả khớp.',
           'Lưu log gốc và phân biệt lần xuất hiện trong sandbox với sự kiện trên thiết bị của tổ chức.'],
  'verify':['Có hostname và khung thời gian từ log thực tế, hoặc ghi rõ chưa tìm thấy máy liên quan.', 'Lưu truy vấn, nguồn log, thời gian tra cứu và kết quả để người khác đối chiếu.'],
  'rollback':'Không thay đổi cấu hình ở bước xác minh. Nếu chưa có kết quả khớp, giữ trạng thái cần bổ sung dữ liệu.'},
 'network': {
  'goal':'Giới hạn liên lạc nghi vấn, đồng thời giữ được đường quản trị và thu thập chứng cứ.',
  'steps':['Đối chiếu IOC với DNS/proxy/firewall và xác nhận endpoint thực sự đã kết nối, không coi mọi IP trong báo cáo là C2.',
           'Nếu có dấu hiệu hoạt động độc hại trên endpoint: đề nghị IR lead cô lập máy qua EDR; ghi lại hostname, người duyệt và thời điểm.',
           'Với IOC đã xác minh: tạo quy tắc chặn có phạm vi và thời hạn tại DNS/proxy/firewall. Loại trừ kill-switch, dịch vụ dùng chung và đích chưa xác minh.',
           'Theo dõi kết nối sau thay đổi và tác động lên ứng dụng nghiệp vụ; ghi mã thay đổi để có thể thu hồi.'],
  'verify':['EDR xác nhận trạng thái cô lập, hoặc log thiết bị mạng cho thấy quy tắc chặn đúng đích đã có hiệu lực.', 'Đường quản trị cần thiết còn hoạt động; không có cảnh báo gián đoạn ngoài phạm vi đã duyệt.'],
  'rollback':'Thu hồi đúng mã quy tắc vừa tạo nếu gây ảnh hưởng ngoài phạm vi; giữ endpoint nghi nhiễm cách ly cho đến khi IR lead quyết định.'},
 'process': {
  'goal':'Xử lý tiến trình đã được xác minh mà không mất chứng cứ hoặc dừng nhầm dịch vụ.',
  'steps':['Lấy process tree trên endpoint: PID, parent PID, đường dẫn, command line, chữ ký và SHA256; PID sandbox không dùng cho máy thật.',
           'Thu thập gói triage và bộ nhớ nếu chính sách yêu cầu; xác nhận tác động với chủ dịch vụ.',
           'Sau khi được duyệt, dùng EDR dừng/quarantine đúng tiến trình hoặc file đã xác minh. Không kết thúc hàng loạt theo tên.'],
  'verify':['Đối tượng đã dừng đúng PID/đường dẫn và có log hành động EDR.', 'Kiểm tra tác vụ/dịch vụ tự khởi động lại tiến trình; xác nhận dịch vụ nghiệp vụ liên quan.'],
  'rollback':'Nếu dừng nhầm dịch vụ, khôi phục từ phiên bản tin cậy theo hướng dẫn của chủ dịch vụ; không chạy lại tệp nghi nhiễm.'},
 'persistence': {
  'goal':'Gỡ cơ chế tự khởi động đã xác nhận, có bản sao cấu hình để đối chiếu.',
  'steps':['Kiểm tra chính xác registry value, scheduled task hoặc service trên endpoint; đối chiếu đích thực thi và SHA256.',
           'Xuất cấu hình gốc và ghi owner/chữ ký/đường dẫn trước khi thay đổi.',
           'Vô hiệu hóa riêng entry độc hại đã duyệt. Không xóa cả nhánh Run, mọi task hay mọi service.'],
  'verify':['Entry đã vô hiệu hóa đúng mục tiêu và không tái tạo sau chu kỳ đăng nhập/khởi động kiểm soát.', 'EDR không còn phát hiện persistence đó; kiểm tra ứng dụng phụ thuộc.'],
  'rollback':'Khôi phục cấu hình đã xuất chỉ khi xác định entry hợp lệ; nếu entry độc hại tái tạo, tiếp tục cách ly và tìm cơ chế còn sót.'},
 'identity': {
  'goal':'Ngăn lạm dụng tài khoản và phiên đăng nhập có khả năng bị lộ.',
  'steps':['Lập danh sách tài khoản đã dùng trên endpoint và thời điểm có dấu hiệu đánh cắp; không mặc định mọi tài khoản đã bị lộ.',
           'Từ thiết bị quản trị sạch, thu hồi session/refresh token và đổi bí mật của tài khoản trong phạm vi đã xác minh; ưu tiên tài khoản đặc quyền.',
           'Rà soát đăng nhập, MFA, OAuth app và thay đổi quyền; bàn giao các bí mật dịch vụ cho chủ hệ thống để xoay vòng có kế hoạch.'],
  'verify':['Có sự kiện thu hồi phiên/đổi bí mật trong hệ thống định danh; session cũ không còn được chấp nhận.', 'Không còn đăng nhập bất thường trong cửa sổ giám sát đã thống nhất với IR lead.'],
  'rollback':'Dùng quy trình khôi phục tài khoản đã xác thực nếu khóa nhầm; không khôi phục mật khẩu/token có nguy cơ đã lộ.'},
 'eradicate': {
  'goal':'Loại bỏ thành phần đã xác minh hoặc dựng lại máy khi không thể chứng minh độ tin cậy.',
  'steps':['Bảo toàn báo cáo, log và file nghi vấn theo quy định; xác định đường dẫn/SHA256 thật. File được drop chưa mặc nhiên là mã độc.',
           'Quarantine bằng EDR các artifact đã xác nhận và kiểm tra persistence đi kèm; ưu tiên cách ly có thể truy vết thay cho xóa tùy tiện.',
           'Nếu ransomware, quyền quản trị bị chiếm hoặc không xác định được phạm vi: thống nhất với IR lead phương án reimage từ image tin cậy.',
           'Không chép lại executable, task, service hoặc cấu hình tự chạy từ hệ thống bị xâm nhập vào máy mới.'],
  'verify':['Có danh sách artifact, kết quả quarantine/reimage và cấu hình persistence đã rà soát.', 'Đối chiếu EDR, tiến trình, kết nối và log sau xử lý; một lần quét sạch không đủ chứng minh hệ thống sạch.'],
  'rollback':'Giữ bằng chứng và bản sao dữ liệu trước thay đổi; khôi phục dữ liệu hợp lệ từ bản sao đã kiểm tra trong môi trường cách ly.'},
 'recover': {
  'goal':'Đưa dịch vụ trở lại từng bước sau khi đạt tiêu chí kỹ thuật và nghiệp vụ.',
  'steps':['Xác minh nguồn image/backup sạch, thời điểm trước xâm nhập và khả năng khôi phục; chạy thử trong vùng mạng cách ly.',
           'Cập nhật bản vá và EDR; thay bí mật liên quan từ máy sạch, rà soát cấu hình bảo vệ và quyền truy cập.',
           'Đối chiếu log tiến trình, persistence, kết nối với IOC; thống nhất cửa sổ giám sát và kiểm thử nghiệp vụ với chủ dịch vụ.',
           'Chỉ kết nối lại từng phần sau khi IR lead và chủ dịch vụ ghi nhận chấp thuận; theo dõi cảnh báo tái nhiễm.'],
  'verify':['Kiểm thử nghiệp vụ đạt và có quyết định cho phép đưa lại vào sử dụng.', 'Cửa sổ giám sát được ghi rõ; không có dấu hiệu tái nhiễm theo các nguồn đã kiểm tra, các điểm thiếu dữ liệu được nêu riêng.'],
  'rollback':'Nếu có dấu hiệu tái nhiễm, cách ly lại, bảo toàn log mới và quay về bản phục hồi đã xác minh; không mở mạng toàn bộ để thử.'},
 'lessons': {
  'goal':'Chốt phạm vi và cải thiện khả năng phát hiện sau sự cố.',
  'steps':['Đối chiếu timeline, tài sản và tài khoản bị ảnh hưởng; ghi riêng quan sát, giả thuyết và phần chưa xác minh.',
           'Lưu quyết định, mã thay đổi, kết quả kiểm tra và báo cáo; phân công người xử lý các khoảng trống phát hiện.',
           'Kiểm thử quy tắc mới bằng dữ liệu được phép dùng trước khi đưa vào giám sát.'],
  'verify':['Chủ sự cố xác nhận báo cáo và danh sách việc còn lại có người phụ trách.', 'Quy tắc phát hiện được kiểm thử cả ca dương và ca âm; không tự công bố độ chính xác khi chưa đánh giá.'],
  'rollback':'Nếu quy tắc gây quá nhiều cảnh báo sai, thu hồi đúng phiên bản và giữ mẫu/log để hiệu chỉnh.'}
}


def apply_guidance(action, result, bundle):
    text=(action.category+' '+action.title).lower(); phase=action.phase.lower()
    if any(w in text for w in ('credential','session','token','tài khoản','mật khẩu')): profile='identity'
    elif 'lessons' in phase: profile='lessons'
    elif 'recovery' in phase: profile='recover'
    elif 'identification' in phase: profile='triage'
    elif any(w in text for w in ('persistence','registry','scheduled task','dịch vụ độc')): profile='persistence'
    elif any(w in text for w in ('inject','tiến trình','process')): profile='process'
    elif 'eradication' in phase: profile='eradicate'
    else: profile='network'
    chosen=PROFILES[profile]
    action.response_profile=profile
    action.objective=chosen['goal']
    action.steps=list(chosen['steps'])
    action.verification=list(chosen['verify'])
    action.rollback=chosen['rollback']
    action.target_scope='Chưa xác minh endpoint thực tế. Tên file, PID và IOC trong nguồn có thể chỉ thuộc môi trường sandbox.'
    action.preconditions=['Đối chiếu hostname, thời điểm và đối tượng với log/EDR thực tế.',
                          'Có người chịu trách nhiệm và phê duyệt thay đổi trước thao tác ảnh hưởng hệ thống.']
    action.related_observations=[{'id':e['id'],'type':e['type'],'value':e['value']} for e in bundle['evidence'] if e['id'] in action.evidence_ids][:6]
    action.risks=[chosen['rollback']]
    if profile=='triage' and any(w in action.title.lower() for w in ('lưu trữ','bảo toàn','thu thập')):
        action.objective='Lưu nguồn và chứng cứ có thể kiểm tra lại trước khi thay đổi hệ thống.'
        action.steps=['Lưu report gốc và IOC; ghi nguồn tải, thời điểm và SHA256 của tệp báo cáo.',
                      'Với endpoint đã xác minh: thu thập log, process tree và gói EDR triage. Thu thập memory/disk khi chính sách yêu cầu trước khi dừng tiến trình hoặc reimage.',
                      'Lưu bản sao trong kho giới hạn truy cập; ghi người thu thập, mã hồ sơ và chuỗi bàn giao. Không coi file export của ứng dụng là bản ảnh forensic.']
        action.verification=['Report gốc đọc được và mã băm khớp sau khi bàn giao.', 'Có danh mục chứng cứ, nguồn thu thập, thời điểm và người nhận; các nguồn thiếu được ghi rõ.']
    if 'host đã mã hóa' in text:
        action.title='Chuẩn bị reimage nếu xác nhận ransomware trên endpoint'
    if 'dừng các tiến trình' in text:
        action.title='Xác minh tiến trình trước khi dừng hoặc quarantine'
    if 'toàn bộ thành phần mã độc' in text:
        action.title='Quarantine các artifact đã xác nhận trên endpoint'
