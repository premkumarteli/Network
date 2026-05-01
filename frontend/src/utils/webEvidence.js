const GENERIC_TITLES = new Set([
  '',
  'untitled',
  'untitled page',
  'new tab',
  'new tab page',
  'browser',
  'about:blank',
]);

const toList = (value) => {
  if (Array.isArray(value)) {
    return value;
  }
  if (value === null || value === undefined || value === '') {
    return [];
  }
  return [value];
};

const uniqueStrings = (values = []) => {
  const result = [];
  values.forEach((value) => {
    const text = String(value || '').trim();
    if (text && !result.includes(text)) {
      result.push(text);
    }
  });
  return result;
};

const extractHost = (value) => {
  const text = String(value || '').trim();
  if (!text) {
    return '';
  }
  try {
    return new URL(text).hostname || '';
  } catch (error) {
    return text;
  }
};

export const normalizeWebRiskLevel = (riskLevel) => {
  const normalized = String(riskLevel || 'safe').trim().toLowerCase();
  if (normalized === 'safe' || normalized === 'low') {
    return 'safe';
  }
  if (normalized === 'medium' || normalized === 'yellow' || normalized === 'warning') {
    return 'medium';
  }
  if (normalized === 'high' || normalized === 'red' || normalized === 'danger') {
    return 'high';
  }
  if (normalized === 'critical') {
    return 'critical';
  }
  return 'safe';
};

export const getWebEvidenceUrls = (item) => uniqueStrings([
  ...toList(item?.page_urls),
  item?.page_url,
]);

export const getWebEvidenceTitles = (item) => uniqueStrings([
  ...toList(item?.page_titles),
  item?.page_title,
]);

export const getWebEvidenceSearchQueries = (item) => uniqueStrings([
  ...toList(item?.search_queries),
  item?.search_query,
]);

export const getWebEvidencePrimaryLabel = (item) => {
  if (!item) {
    return 'Browser Evidence';
  }

  const pageTitle = String(item.group_label || item.page_title || '').trim();
  if (pageTitle && !GENERIC_TITLES.has(pageTitle.toLowerCase())) {
    return pageTitle;
  }

  const contentId = String(item.content_id || '').trim();
  if (contentId) {
    return contentId;
  }

  const domain = String(item.base_domain || '').trim();
  if (domain) {
    return domain;
  }

  const urls = getWebEvidenceUrls(item);
  if (urls.length > 0) {
    return urls[0];
  }

  return 'Browser Evidence';
};

export const getWebEvidenceScopeLabel = (item) => {
  const eventCount = Math.max(Number(item?.event_count) || 1, 1);
  const urlCount = getWebEvidenceUrls(item).length;
  const titleCount = getWebEvidenceTitles(item).length;
  return {
    eventCount,
    urlCount,
    titleCount,
    text: `${eventCount} event${eventCount === 1 ? '' : 's'} · ${urlCount} URL${urlCount === 1 ? '' : 's'} · ${titleCount} title${titleCount === 1 ? '' : 's'}`,
  };
};

export const matchesWebEvidenceFilters = (item, filters = {}) => {
  const query = String(filters.query || '').trim().toLowerCase();
  const browserFilter = String(filters.browser || 'all').trim().toLowerCase();
  const domainFilter = String(filters.domain || 'all').trim().toLowerCase();
  const riskFilter = String(filters.risk || 'all').trim().toLowerCase();

  const browserName = String(item?.browser_name || '').trim().toLowerCase();
  const processName = String(item?.process_name || '').trim().toLowerCase();
  const riskLevel = normalizeWebRiskLevel(item?.risk_level);
  const urls = getWebEvidenceUrls(item);
  const searchableDomain = uniqueStrings([
    item?.base_domain,
    ...urls.map(extractHost),
  ]).join(' ').toLowerCase();

  if (browserFilter !== 'all' && browserName !== browserFilter && processName !== browserFilter) {
    return false;
  }

  if (domainFilter !== 'all' && !searchableDomain.includes(domainFilter)) {
    return false;
  }

  if (riskFilter !== 'all' && riskLevel !== riskFilter) {
    return false;
  }

  if (!query) {
    return true;
  }

  const haystack = uniqueStrings([
    item?.group_label,
    item?.page_title,
    item?.base_domain,
    item?.page_url,
    item?.content_id,
    item?.search_query,
    item?.browser_name,
    item?.process_name,
    ...getWebEvidenceTitles(item),
    ...urls,
    ...getWebEvidenceSearchQueries(item),
    ...toList(item?.content_ids),
  ]).join(' ').toLowerCase();

  return haystack.includes(query);
};
