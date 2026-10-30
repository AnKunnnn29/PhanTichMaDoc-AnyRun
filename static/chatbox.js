let chatCaseId=null;
let chatReturnFocus=null;
function chatConversation() {
  return [...document.querySelectorAll('#chat-messages .chat-user,#chat-messages .chat-assistant')]
    .filter(el=>el.id!=='ai-answer')
    .map(el=>({role:el.classList.contains('chat-user')?'user':'assistant',content:(el.dataset.answer||el.textContent).slice(0,2000)}))
    .slice(0,-1).slice(-6);
}
function toggleChat(open) {
  const panel=document.getElementById('chat-panel');
  if(open){chatReturnFocus=document.activeElement;panel.showModal();refreshChatStatus();document.getElementById('ai-question').focus();}
  else {stopAI(false);panel.close();chatReturnFocus?.focus();}
}
function updateChatCase(data) {
  const name=data.file?.name||data.playbook?.malware_name||'Hồ sơ đang mở';
  document.getElementById('chat-case-name').textContent=name+' · Nguồn báo cáo; chưa xác minh endpoint thực tế';
  if(chatCaseId===data.case_id) return;
  stopAI(false);chatCaseId=data.case_id;
  document.getElementById('chat-messages').innerHTML='<div id="ai-answer" class="chat-welcome">Bạn có thể hỏi về bằng chứng, thứ tự xử lý hoặc cách xác minh sau khắc phục. Câu trả lời cần được đối chiếu với log thực tế.</div>';
}
function appendChatQuestion(question) {
  const old=document.getElementById('ai-answer');if(old) old.removeAttribute('id');
  const root=document.getElementById('chat-messages');
  const user=document.createElement('p');user.className='chat-user';user.textContent=question;root.appendChild(user);
  const answer=document.createElement('div');answer.id='ai-answer';answer.className='chat-assistant';answer.textContent='Đang chuẩn bị câu trả lời…';root.appendChild(answer);
  root.scrollTop=root.scrollHeight;
  document.getElementById('ai-question').value='';
}
async function refreshChatStatus() {
  const el=document.getElementById('chat-provider');
  try {
    const j=await (await fetch('/api/ai/status')).json();
    if(j.data.provider==='ollama') {
      const status=await (await fetch('/api/ai/local-status')).json();
      el.textContent=status.data.ready?'AI trên máy · '+j.data.ollama_model:'AI trên máy chưa sẵn sàng · Kiểm tra Ollama';
    } else el.textContent=j.data.provider==='local'||!j.data.openai_configured?'Hỗ trợ theo quy tắc · Chưa có mô hình AI kết nối':'AI đã cấu hình · '+j.data.openai_model;
    if(j.data.hash_lookup_configured)el.textContent+=' · Có tra cứu mã băm';
  } catch(_){el.textContent='Chưa kiểm tra được kết nối AI';}
}
function clearChat() {stopAI(false);chatCaseId=null;if(G.data)updateChatCase(G.data);else document.getElementById('chat-messages').innerHTML='<div id="ai-answer" class="chat-welcome">Mở một hồ sơ để hỏi về kết quả và biện pháp xử lý.</div>';}
document.addEventListener('DOMContentLoaded',()=>{
  document.getElementById('chat-form').addEventListener('submit',e=>{e.preventDefault();askAI();});
  document.getElementById('chat-panel').addEventListener('cancel',()=>stopAI(false));
});
