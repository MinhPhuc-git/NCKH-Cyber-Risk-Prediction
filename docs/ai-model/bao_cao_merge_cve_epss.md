# Báo cáo: Xây dựng dataset CVE–EPSS cho bài toán dự đoán khả năng bị khai thác

## 1. Cột nào nên dùng làm target dự đoán "khả năng bị tấn công"?

**Trả lời: dùng cột `epss`** (thang 0–1, từ file `epss_scores-2026-07-16.csv`), **không dùng** `percentile`, `base_score`, hay `severity`.

Lý do:
- `epss` = xác suất một CVE bị khai thác thực tế trong 30 ngày tới — đúng định nghĩa "khả năng bị tấn công" bạn cần, do FIRST.org tính từ nhiều tín hiệu (exploit code công khai, mention trên threat intel, loại lỗi, v.v.).
- `percentile` chỉ là **thứ hạng tương đối** của `epss` trong toàn bộ CVE tại thời điểm đó — gần như là hàm số của chính `epss`, dùng làm target sẽ trùng lặp thông tin, không nên dùng cả hai cùng lúc làm target hay feature.
- `base_score` (CVSS) đo **mức độ nghiêm trọng nếu bị khai thác thành công**, không đo **xác suất bị khai thác** — hai khái niệm khác nhau, không thể thay thế cho nhau.

**Khi nhận dữ liệu mới từ agent (giống format `agent_data_labeled.json` bạn gửi trước)**, model sẽ predict ra 1 con số `epss` cho CVE đó dựa trên các field CVSS/CWE mà agent cung cấp — xem mapping field ở mục 2.

**Gợi ý bổ sung:** nếu mục đích cuối là hệ thống cảnh báo/ưu tiên vá lỗi, có thể tạo thêm **target phụ dạng phân loại** từ `epss_risk_bucket` (very_low / low / medium / high, xem mục 3) — dễ dùng để set ngưỡng cảnh báo hơn là số thập phân thô.

---

## 2. Mapping giữa 2 file và với format dữ liệu agent

### 2.1. Mapping giữa `cve_standard.csv` và `epss_scores-2026-07-16.csv`

| Trường nối | File 1 (`cve_standard.csv`) | File 2 (`epss_scores...csv`) |
|---|---|---|
| Khóa join | `cve_id` | `cve` |

- File EPSS có dòng metadata đầu (`#model_version:v2026.06.15,score_date:2026-07-16...`) → phải `skiprows=1` khi đọc.
- Join kiểu **inner**: chỉ giữ CVE có mặt ở cả 2 file.
- Kết quả: **348,893 / 349,202** CVE ở file 1 khớp được với EPSS (309 CVE trong `cve_standard.csv` không có EPSS tương ứng, bị loại).

### 2.2. Mapping field giữa dataset chuẩn và format agent (để dùng khi predict CVE mới)

Khi agent (LLM) tạo dữ liệu label như `agent_data_labeled.json` trước đó, đây là bảng ánh xạ tên trường sang cột dataset đã train, **bắt buộc dùng đúng bảng này khi encode input cho model**, tránh sai lệch tên cột:

| Field trong agent JSON | Cột tương ứng trong dataset | Ghi chú |
|---|---|---|
| `av_label` | `attack_vector` | khớp trực tiếp (NETWORK/LOCAL/...) |
| `ac_label` | `attack_complexity` | khớp trực tiếp (LOW/HIGH) |
| `pr_label` | `privileges_required` | khớp trực tiếp |
| `ui_label` | `user_interaction` | khớp trực tiếp — lưu ý dataset có thêm giá trị `PASSIVE`/`ACTIVE` (CVSS 4.0) mà agent hiện chưa sinh ra |
| `scope_label` | `scope` | khớp trực tiếp |
| `c_label` / `i_label` / `a_label` | `confidentiality` / `integrity` / `availability` | khớp trực tiếp |
| `cwe_id` | `cwe_id` (hoặc `cwe_id_grouped` nếu dùng bản đã gộp rare) | cần chuẩn hóa format `CWE-xxx` |
| `base_score` | `base_score` | khớp trực tiếp |
| `severity_label` | *(không có cột tương ứng trực tiếp)* | dataset không có cột severity string — có thể tự tính lại từ `base_score` theo ngưỡng CVSS chuẩn nếu cần |
| `technical_impact_label` | *(không có trong `cve_standard.csv`)* | đây là field tự agent sinh thêm (không thuộc chuẩn NVD/CVSS) — nếu muốn dùng làm feature, cần agent gán nhãn cho **toàn bộ** 348,893 dòng training, không chỉ dòng mới, để nhất quán |

**Lưu ý quan trọng:** các field `*_reason` (giải thích tiếng Việt) trong agent JSON chỉ nên dùng để review/giải thích cho con người, **không đưa vào làm feature training** — chúng là text tự do do agent sinh ra, không nhất quán về mặt thống kê.

### 2.3. Xử lý dữ liệu khi mapping (đã áp dụng vào file kết quả)

- **CVSS version lẫn lộn (2.0/3.0/3.1/4.0 cùng tồn tại)**: giữ nguyên cột `cvss_version` + thêm cờ `is_cvss3_or_higher` để model biết phân biệt, thay vì coi mọi vector cùng 1 thang.
- **1,573 dòng có `cvss_version = -1`** (không có CVSS hợp lệ): thêm cờ `has_valid_cvss = 0` thay vì xóa hoặc impute giá trị giả.
- **CWE generic** (`NVD-CWE-noinfo`, `NVD-CWE-Other`, chiếm 65,098 dòng ~18.6%): đánh dấu cờ `cwe_is_generic = 1` — đây không phải CWE thật, cần model biết để không coi là 1 category có ý nghĩa ngang các CWE cụ thể khác.
- **CWE cardinality cao** (695 giá trị gốc): gộp các CWE có ≤5 mẫu thành `OTHER_RARE` → còn **423 nhóm**, giảm nguy cơ overfit lên CWE hiếm đã phân tích ở các lượt trước.
- Thêm `epss_risk_bucket` (very_low/low/medium/high) để hỗ trợ stratified split và đánh giá theo từng mức rủi ro thay vì chỉ nhìn MAE tổng.

---

## 3. Kết quả sau khi merge

| Chỉ số | Giá trị |
|---|---|
| Tổng số dòng sau merge | **348,893** |
| EPSS rất thấp (< 0.01) | 205,453 (58.9%) |
| EPSS thấp (0.01–0.1) | 126,277 (36.2%) |
| EPSS trung bình (0.1–0.3) | 10,181 (2.9%) |
| **EPSS cao (> 0.3)** | **6,982 (2.0%)** — tăng ~**97 lần** so với 72 mẫu ở dataset cũ 13k dòng |
| Số CWE gốc → sau gộp rare | 695 → 423 |
| Dòng thiếu CVSS hợp lệ | 1,573 (0.45%) |
| Dòng CWE generic (không xác định) | 65,098 (18.6%) |

So với dataset cũ (13,112 dòng, chỉ 72 mẫu EPSS>0.3), dataset mới đã giải quyết đúng vấn đề mất cân bằng đã chẩn đoán trước đó — đủ cơ sở để train lại model mà không bị "collapse về mean" ở nhóm rủi ro cao.

---

## 4. File đã tạo

- `cve_epss_merged_v2.csv` — bản đầy đủ (có `description`, ~200MB)
- `cve_epss_merged_v2_light.csv` — bản không có `description`, nhẹ hơn (~79MB), **khuyên dùng để train** vì không cần text mô tả cho model dạng bảng (tabular)

## 5. Đề xuất bước tiếp theo

1. Train lại XGBoost với stratified split theo `epss_risk_bucket` + `sample_weight` ưu tiên nhóm rủi ro cao (đã đề xuất ở lượt trước).
2. Đánh giá riêng theo từng bucket, không chỉ MAE/R2 tổng.
3. Với 1,573 dòng thiếu CVSS và 65,098 dòng CWE generic — cân nhắc train thêm 1 phiên bản loại bỏ các dòng này để so sánh, xem chúng có làm nhiễu model không.
