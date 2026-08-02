from pathlib import Path
from datetime import datetime
import shutil
import re

root = Path(r"D:\LuanVan\test\cyrp-platform-phase2")
path = root / "apps" / "user-web" / "src" / "app" / "ai-predictions" / "ai-predictions-client.tsx"

backup = path.with_suffix(".tsx.bak-global-ai-sort-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

old_pattern = r"""  const load = useCallback\(async \(\) => \{
[\s\S]*?
  \}, \[page, query, riskLevel\]\);"""

new_block = r'''  const load = useCallback(async () => {
    setLoading(true);

    try {
      const pageSize = 25;
      const fetchLimit = 100;
      const allItems: VulnerabilityItem[] = [];

      let apiTotal = 0;
      let apiTotalPages = 1;

      for (let pageNumber = 1; pageNumber <= apiTotalPages && pageNumber <= 50; pageNumber += 1) {
        const params = new URLSearchParams({
          page: String(pageNumber),
          limit: String(fetchLimit),
          status: 'ACTIVE',
        });

        if (query) {
          params.set('query', query);
        }

        const response = await fetch(`/api/vulnerabilities?${params.toString()}`, {
          cache: 'no-store',
        });

        const payload = (await response.json()) as Pagination<VulnerabilityItem> & {
          message?: string;
        };

        if (!response.ok) {
          throw new Error(payload.message ?? 'Không thể tải kết quả AI');
        }

        const pageItems = Array.isArray(payload.items) ? payload.items : [];
        allItems.push(...pageItems);

        if (pageNumber === 1) {
          apiTotal = typeof payload.total === 'number' ? payload.total : pageItems.length;
          apiTotalPages =
            typeof payload.totalPages === 'number' && payload.totalPages > 0
              ? payload.totalPages
              : Math.max(1, Math.ceil(apiTotal / fetchLimit));
        }

        if (pageItems.length === 0 || allItems.length >= apiTotal) {
          break;
        }
      }

      const sortedItems = sortAndFilterByAiRiskLevel(allItems, riskLevel);
      const totalItems = sortedItems.length;
      const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
      const safePage = Math.min(page, totalPages);
      const startIndex = (safePage - 1) * pageSize;
      const visibleItems = sortedItems.slice(startIndex, startIndex + pageSize);

      if (safePage !== page) {
        setPage(safePage);
      }

      setData({
        page: safePage,
        limit: pageSize,
        total: totalItems,
        totalPages,
        items: visibleItems,
      });

      setError('');
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : 'Không thể tải kết quả AI');
    } finally {
      setLoading(false);
    }
  }, [page, query, riskLevel]);'''

text, count = re.subn(old_pattern, new_block, text, count=1)

if count != 1:
    raise SystemExit("Không thay được block load. Cần gửi lại đoạn quanh const load = useCallback.")

text = text.replace(
    "{sortAndFilterByAiRiskLevel(data?.items ?? [], riskLevel).map((item) => {",
    "{(data?.items ?? []).map((item) => {",
)

# Không gửi riskLevel lên API nữa, vì lọc local sau khi gom toàn bộ dữ liệu.
text = text.replace("      if (riskLevel) params.set('riskLevel', riskLevel);\n", "")

path.write_text(text, encoding="utf-8")

print("Patched:", path)
print("Backup:", backup)
