(() => {
  const page = document.body.dataset.page || "dashboard";
  const $ = (selector) => document.querySelector(selector);
  const esc = (value) => String(value ?? "—").replace(/[&<>'"]/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;","\"":"&quot;"}[char]));
  const pretty = (value) => value === null || value === undefined || value === "" ? "UNKNOWN" : String(value);
  const statusClass = (value) => String(value || "UNKNOWN").toLowerCase();
  const statusLabels = { PASS: "ĐẠT", FAIL: "CẦN XEM LẠI", UNKNOWN: "CHƯA ĐỦ DỮ LIỆU", PARTIAL: "MỘT PHẦN", BLOCKED: "BỊ CHẶN" };
  const pill = (value) => { const key = String(value || "UNKNOWN").toUpperCase(); return `<span class="status-pill ${statusClass(key)}">${esc(statusLabels[key] || key)}</span>`; };
  const toast = (message) => { const node = $("#toast"); if (!node) return; node.textContent = message; node.classList.add("show"); setTimeout(() => node.classList.remove("show"), 2400); };
  const api = async (url, options = {}) => { const response = await fetch(url, options); const data = await response.json(); if (!response.ok) throw new Error(data.error || "API request failed"); return data; };
  const setUpdated = (date) => { const node = $("#lastUpdated"); if (node && date) node.textContent = `Cập nhật ${new Date(date).toLocaleString("vi-VN")}`; };
  const showError = (message) => { const node = $("#pageError"); if (!node) return; node.hidden = false; node.innerHTML = `<strong>Không kết nối được collector</strong><span>${esc(message || "Hãy kiểm tra Terminal server và nhấn Làm mới.")}</span>`; };
  const clearError = () => { const node = $("#pageError"); if (node) { node.hidden = true; node.textContent = ""; } };
  let latestMonitorData = null;

  document.querySelectorAll(".nav-item").forEach((item) => { if (item.dataset.page === page) item.classList.add("active"); });
  $("#menuToggle")?.addEventListener("click", () => $("#sidebar")?.classList.toggle("open"));
  $("#refreshButton")?.addEventListener("click", () => { toast("Đang đọc lại trạng thái…"); loadPage(); });

  const renderDashboard = (data) => {
    const grid = $("#metricGrid");
    if (grid) grid.innerHTML = data.cards.map((card) => `<article class="metric-card"><div class="metric-card-head"><span>${esc(card.label)}</span><span class="metric-card-icon">${card.id === "ssh" ? "⌁" : card.id === "ufw" ? "◈" : card.id === "fail2ban" ? "⊘" : "▣"}</span></div><h3>${pill(card.value)}</h3><small>${esc(card.detail)}</small></article>`).join("");
    const banner = $("#overallBanner"); const title = $("#overallTitle"); const detail = $("#overallDetail");
    if (banner) banner.className = `status-banner ${statusClass(data.overall) === "pass" ? "" : statusClass(data.overall) === "unknown" ? "warning" : "danger"}`;
    if (title) title.textContent = data.overall === "PASS" ? "Baseline bảo mật đang ổn định" : data.overall === "UNKNOWN" ? "Chưa đủ dữ liệu để kết luận" : "Có hạng mục cần xem lại";
    if (detail) detail.textContent = data.warnings?.length ? "Một số kiểm tra cần quyền sudo. Hãy đóng server, chạy lại launcher và nhập mật khẩu Ubuntu." : `Collector đọc ${data.cards.length} lớp bảo vệ; không thay đổi cấu hình Ubuntu.`;
    if ($("#snapshotTime")) $("#snapshotTime").textContent = new Date(data.collected_at).toLocaleTimeString("vi-VN");
    if ($("#systemName")) $("#systemName").textContent = `${data.system.hostname || "Ubuntu VM"} · ${data.system.architecture || "UNKNOWN"}`;
    const system = data.system; const rows = [["Tên máy",system.hostname],["Hệ điều hành",system.os],["Kiến trúc",system.architecture],["Kernel",system.kernel],["Bộ nhớ",system.memory],["Ổ đĩa root",system.disk],["IP đã ẩn",(system.ips || []).join(" ") || "UNKNOWN"]];
    if ($("#systemList")) $("#systemList").innerHTML = rows.map(([key,value]) => `<div class="system-row"><span>${esc(key)}</span><strong>${esc(value)}</strong></div>`).join("");
    clearError();
    setUpdated(data.collected_at);
  };

  const rowsFor = (data) => {
    if (page === "ssh") return [["Dịch vụ",data.service],["Tự khởi động",data.enabled],["Kiểm tra cú pháp",data.validation],...["port","maxauthtries","permitrootlogin","pubkeyauthentication","passwordauthentication"].map((key) => [key,data.config?.[key]])];
    if (page === "ufw") return [["Trạng thái",data.status],["Mặc định inbound",data.default_incoming],["Mặc định outbound",data.default_outgoing],["Rule đang đọc được",data.rules?.length ? data.rules.join(" · ") : "Không có rule đọc được"]];
    if (page === "fail2ban") return [["Dịch vụ",data.service],["Jail",data.jail],["Đang lỗi",data.currently_failed],["Đang bị ban",data.currently_banned],["Tổng số ban",data.total_banned],["Bằng chứng ban",data.ban_test_status]];
    return [["Đường dẫn",data.path],["Mode",data.mode],["Owner có quyền đọc",data.owner_readable === true ? "yes" : data.owner_readable === false ? "no" : "UNKNOWN"],["testuser có quyền đọc",data.testuser_readable === true ? "yes" : data.testuser_readable === false ? "no" : "UNKNOWN"],["Stat gốc",data.raw]];
  };
  const renderMonitor = (data) => {
    latestMonitorData = data;
    const result = data.status || data.validation || (data.service ? (data.service === "active" ? "PASS" : "FAIL") : "UNKNOWN");
    if ($("#monitorStatus")) $("#monitorStatus").innerHTML = pill(result);
    if ($("#monitorMain")) $("#monitorMain").innerHTML = rowsFor(data).map(([key,value]) => `<div class="data-row"><span>${esc(key)}</span><strong>${esc(pretty(value))}</strong></div>`).join("");
    if ($("#rawData")) $("#rawData").textContent = JSON.stringify(data, null, 2);
    if ($("#permissionNote")) { $("#permissionNote").hidden = !data.warning; $("#permissionNote").textContent = data.warning || ""; }
    clearError();
    setUpdated(new Date().toISOString());
  };

  const loadMonitor = async () => {
    const endpoint = {ssh:"/api/ssh",ufw:"/api/ufw",fail2ban:"/api/fail2ban",permissions:"/api/permissions"}[page];
    try { renderMonitor(await api(endpoint)); } catch (error) { if ($("#rawData")) $("#rawData").textContent = error.message; showError(error.message); toast("Không đọc được dữ liệu monitor"); }
  };
  const monitorExplanation = (data) => {
    if (!data) return "Chưa có dữ liệu. Nhấn Kiểm tra ngay để đọc trạng thái Ubuntu.";
    if (page === "ssh") return data.status === "PASS" ? "SSH đang đáp ứng các điều kiện bảo vệ đã định nghĩa: dịch vụ hoạt động, cấu hình hợp lệ và không cho root đăng nhập trực tiếp." : "Kết quả SSH chưa đạt hoặc chưa đủ dữ liệu. Hãy đối chiếu PermitRootLogin, xác thực key, mật khẩu và MaxAuthTries. Nếu có cảnh báo quyền, chạy sudo -v trước khi mở dashboard.";
    if (page === "ufw") return data.status === "PASS" ? "UFW đang active, inbound mặc định deny và outbound mặc định allow. Rule port 22 là ngoại lệ được cho phép để quản trị SSH." : "UFW chưa thể kết luận đạt. Kiểm tra trạng thái active, chính sách mặc định và rule đang đọc được. UFW cần quyền sudo để đọc.";
    if (page === "fail2ban") return data.status === "PASS" ? `Jail ${data.jail || "sshd"} đang hoạt động. Số IP bị ban hiện tại là ${data.currently_banned ?? "chưa rõ"}; bằng 0 chỉ có nghĩa chưa có sự kiện ban.` : "Fail2ban chưa đủ điều kiện kết luận. Cần kiểm tra service và jail sshd; hãy chạy sudo -v trước khi mở dashboard.";
    return data.status === "PASS" ? "File đang dùng mode 600: owner có thể đọc, còn testuser không có quyền đọc. Nội dung secret không được đưa lên website." : "Permissions chưa thể kết luận. Kiểm tra mode file và trạng thái quyền đọc của owner/testuser.";
  };
  const setupMonitorActions = () => {
    $("#checkNow")?.addEventListener("click", async () => { const button = $("#checkNow"); button.disabled = true; button.textContent = "Đang kiểm tra…"; toast("Đang đọc dữ liệu Ubuntu"); await loadMonitor(); button.disabled = false; button.textContent = "Kiểm tra ngay"; });
    $("#explainButton")?.addEventListener("click", () => { const box = $("#explanationBox"); if (!box) return; box.hidden = !box.hidden; box.innerHTML = `<strong>Kết luận dễ hiểu</strong><span>${esc(monitorExplanation(latestMonitorData))}</span>`; });
    $("#toggleRaw")?.addEventListener("click", () => { const panel = $("#rawPanel"); if (!panel) return; panel.hidden = !panel.hidden; $("#toggleRaw").textContent = panel.hidden ? "Xem JSON" : "Ẩn JSON"; });
  };
  const renderReports = (data) => {
    const body = $("#reportsBody"); const items = data.items || [];
    if ($("#reportCount")) $("#reportCount").textContent = `${items.length} báo cáo`;
    if (!body) return;
    body.innerHTML = items.length ? items.map((item) => `<tr><td><strong>${esc(item.name)}</strong></td><td>${esc(new Date(item.modified).toLocaleString("vi-VN"))}</td><td>${(item.size / 1024).toFixed(1)} KB</td><td><a class="download-link" href="/api/reports/${encodeURIComponent(item.name)}">Tải xuống ↓</a></td></tr>`).join("") : `<tr><td colspan="4" class="empty-state">Chưa có audit report hợp lệ.</td></tr>`;
  };
  const loadReports = async () => { try { renderReports(await api("/api/reports")); setUpdated(new Date().toISOString()); } catch (error) { toast(error.message); } };
  $("#runAudit")?.addEventListener("click", async () => { const button = $("#runAudit"); if (button) { button.disabled = true; button.textContent = "Đang audit…"; } try { const result = await api("/api/audit", {method: "POST"}); toast("Audit read-only đã hoàn tất"); if ($("#auditResult")) $("#auditResult").textContent = "Đã tạo report mới"; if ($("#auditOutputPanel")) $("#auditOutputPanel").hidden = false; if ($("#auditOutput")) $("#auditOutput").textContent = result.output || "Audit hoàn tất nhưng không có output."; await loadReports(); } catch (error) { if ($("#auditResult")) $("#auditResult").textContent = "Audit chưa chạy được"; toast(error.message); } finally { if (button) { button.disabled = false; button.textContent = "Chạy audit read-only"; } } });
  const renderTests = (data) => {
    const items = data.items || []; const counts = items.reduce((acc, item) => { const key = (item.Status || "UNKNOWN").toUpperCase(); acc[key] = (acc[key] || 0) + 1; return acc; }, {});
    if ($("#testSummary")) $("#testSummary").innerHTML = ["PASS","PARTIAL","BLOCKED","FAIL"].filter((key) => counts[key]).map((key) => `<span class="summary-chip ${key.toLowerCase()}">${esc(statusLabels[key] || key)} ${counts[key]}</span>`).join("");
    if ($("#testGrid")) {
      $("#testGrid").innerHTML = items.map((item) => `<article class="test-card"><div class="test-id">${esc(item.ID)}</div><div><h4>${esc(item.Title)}</h4><p>${esc(item.Actual || item.Expected || "Chưa có mô tả")}</p><button class="test-detail-button" data-test-id="${esc(item.ID)}">Xem cách kiểm tra</button><div class="test-details" id="details-${esc(item.ID)}" hidden><div><b>Kỳ vọng:</b> ${esc(item.Expected)}</div><div><b>Thao tác:</b> <code>${esc(item.Command_or_location)}</code></div><div><b>Minh chứng:</b> ${esc(item.Evidence)}</div></div></div><div>${pill(item.Status)}</div></article>`).join("") || `<div class="empty-state">Không đọc được tests/test_cases.csv.</div>`;
      document.querySelectorAll(".test-detail-button").forEach((button) => button.addEventListener("click", () => { const details = $(`#details-${button.dataset.testId}`); if (!details) return; details.hidden = !details.hidden; button.textContent = details.hidden ? "Xem cách kiểm tra" : "Ẩn chi tiết"; }));
    }
  };
  const loadTests = async () => { try { renderTests(await api("/api/tests")); setUpdated(new Date().toISOString()); } catch (error) { toast(error.message); } };
  $("#copyJson")?.addEventListener("click", async () => { try { await navigator.clipboard.writeText($("#rawData").textContent); toast("Đã sao chép JSON"); } catch (_) { toast("Trình duyệt không cho phép sao chép"); } });
  const loadPage = async () => { if (page === "dashboard") { try { renderDashboard(await api("/api/snapshot")); } catch (error) { showError(error.message); toast("Không đọc được snapshot Ubuntu"); } } else if (["ssh","ufw","fail2ban","permissions"].includes(page)) { setupMonitorActions(); await loadMonitor(); } else if (page === "reports") await loadReports(); else if (page === "tests") await loadTests(); };
  loadPage();
})();
