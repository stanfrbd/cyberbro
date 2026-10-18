<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import {
  Activity,
  ArrowDownToLine,
  ArrowLeft,
  ArrowRight,
  ArrowUpRight,
  Box,
  Check,
  CheckCheck,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Clock3,
  Copy,
  Database,
  ExternalLink,
  FileJson,
  Fingerprint,
  FlaskConical,
  Globe2,
  History,
  Layers,
  LayoutDashboard,
  ListFilter,
  LoaderCircle,
  Moon,
  Network,
  Plus,
  Search,
  Settings2,
  Shield,
  ShieldAlert,
  Sun,
  X,
} from "lucide-vue-next";
import {
  asRecord,
  context,
  demoEngines,
  demoRows,
  engineEntries,
  engineLabel,
  signal,
  signalLabel,
  type ObservableResult,
  type Signal,
} from "./data";

const params = new URLSearchParams(location.search);
const demo = params.get("demo") === "1";
const bootstrap = window.CYBERBRO_CONFIG;
const analysisId = ref(params.get("analysis") ?? "");
const view = ref<"results" | "new">(
  demo || analysisId.value ? "results" : "new",
);
const rows = ref<ObservableResult[]>(demo ? structuredClone(demoRows) : []);
const engines = ref<string[]>(demo ? demoEngines : []);
const selected = ref<ObservableResult | null>(
  window.matchMedia("(max-width: 1000px)").matches
    ? null
    : (rows.value[0] ?? null),
);
const query = ref("");
const typeFilter = ref("All types");
const activeFilter = ref<"all" | Signal>("all");
const page = ref(1);
const pageSize = 8;
const tab = ref<"overview" | "json">("overview");
const exporting = ref(false);
const columnsOpen = ref(false);
const showNetwork = ref(true);
const showAbuse = ref(true);
const toast = ref("");
const error = ref("");
const busy = ref(false);
const rawInput = ref("");
const ignoreCache = ref(false);
const chosenEngines = ref<string[]>(
  ["reverse_dns", "rdap_whois"].filter(
    (name) =>
      !bootstrap?.enabledEngines.length ||
      bootstrap.enabledEngines.includes(name),
  ),
);
const engineQuery = ref("");
const dark = ref(localStorage.getItem("cyberbro-ui-theme") !== "light");
const availableEngines = computed(() =>
  (demo ? demoEngines : (bootstrap?.engines ?? [])).filter(
    (name) =>
      !bootstrap?.enabledEngines.length ||
      bootstrap.enabledEngines.includes(name),
  ),
);
const filteredEngines = computed(() =>
  availableEngines.value.filter((name) =>
    engineLabel(name).toLowerCase().includes(engineQuery.value.toLowerCase()),
  ),
);
const types = computed(() => [...new Set(rows.value.map((row) => row.type))]);
const filtered = computed(() =>
  rows.value.filter(
    (row) =>
      (typeFilter.value === "All types" || row.type === typeFilter.value) &&
      (activeFilter.value === "all" || signal(row) === activeFilter.value) &&
      JSON.stringify(row).toLowerCase().includes(query.value.toLowerCase()),
  ),
);
const pageCount = computed(() =>
  Math.max(1, Math.ceil(filtered.value.length / pageSize)),
);
const visible = computed(() =>
  filtered.value.slice((page.value - 1) * pageSize, page.value * pageSize),
);
const signalsCount = computed(
  () => rows.value.filter((row) => signal(row) === "signals").length,
);
const missingCount = computed(
  () => rows.value.filter((row) => signal(row) === "unavailable").length,
);
const sourceCount = computed(
  () =>
    new Set(
      rows.value.flatMap((row) =>
        engineEntries(row)
          .filter(([, value]) => value && !value.error)
          .map(([name]) => name),
      ),
    ).size,
);
const selectedEntries = computed(() =>
  selected.value ? engineEntries(selected.value) : [],
);
const detailEntries = computed(() =>
  [
    ...new Set([
      ...engines.value,
      ...selectedEntries.value.map(([name]) => name),
    ]),
  ].map(
    (name) =>
      [name, selected.value ? asRecord(selected.value[name]) : null] as const,
  ),
);
const filterTabs: { key: "all" | Signal; label: string }[] = [
  { key: "all", label: "All observables" },
  { key: "signals", label: "Signals found" },
  { key: "no-detections", label: "No VT detections" },
  { key: "unavailable", label: "Not assessed" },
];
watch([query, typeFilter, activeFilter], () => {
  page.value = 1;
});
watch(dark, (value) =>
  localStorage.setItem("cyberbro-ui-theme", value ? "dark" : "light"),
);
let toastTimer: ReturnType<typeof setTimeout> | undefined;
let pollingTimer: ReturnType<typeof setTimeout> | undefined;
let disposed = false;
onBeforeUnmount(() => {
  disposed = true;
  clearTimeout(toastTimer);
  clearTimeout(pollingTimer);
});
function notify(message: string): void {
  toast.value = message;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.value = "";
  }, 3000);
}
async function copy(value: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(value);
    notify("Copied to clipboard");
  } catch {
    notify("Clipboard unavailable in this browser");
  }
}
function choose(row: ObservableResult): void {
  selected.value = row;
  tab.value = "overview";
}
function sourceStatus(value: Record<string, unknown> | null): string {
  return value?.error
    ? "Error"
    : value
      ? "Response received"
      : "No data returned";
}
function safeLink(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  try {
    const url = new URL(value);
    return ["https:", "http:"].includes(url.protocol) ? url.href : undefined;
  } catch {
    return undefined;
  }
}
function download(format: "csv" | "json"): void {
  exporting.value = false;
  if (format === "json") {
    saveBlob(
      JSON.stringify(filtered.value, null, 2),
      "application/json",
      "json",
    );
  } else {
    const escape = (value: string): string =>
      '"' +
      (/^[=+@\-\t\r]/.test(value) ? "'" + value : value).replaceAll('"', '""') +
      '"';
    const header = [
      "Observable",
      "Type",
      "Signals",
      "VirusTotal",
      "AbuseIPDB",
      "Network",
    ];
    const data = filtered.value.map((row) =>
      [
        row.observable,
        row.type,
        signalLabel(signal(row)),
        String(asRecord(row.virustotal)?.detection_ratio ?? ""),
        String(asRecord(row.abuseipdb)?.abuseConfidenceScore ?? ""),
        context(row).network,
      ]
        .map(escape)
        .join(","),
    );
    saveBlob(
      [header.map(escape).join(","), ...data].join("\r\n"),
      "text/csv;charset=utf-8",
      "csv",
    );
  }
}
function saveBlob(data: string, mime: string, extension: string): void {
  const url = URL.createObjectURL(new Blob([data], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = `cyberbro-${demo ? "demo" : analysisId.value}.${extension}`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function toggleEngine(name: string): void {
  chosenEngines.value = chosenEngines.value.includes(name)
    ? chosenEngines.value.filter((key) => key !== name)
    : [...chosenEngines.value, name];
}
function apiUrl(path: string): string {
  if (!bootstrap)
    throw new Error(
      "Open /ui on your Cyberbro instance to connect the API, or add ?demo=1 for the preview.",
    );
  return `/${bootstrap.apiPrefix.replace(/^\/+|\/+$/g, "")}/${path}`;
}
async function getJson(path: string, options?: RequestInit): Promise<unknown> {
  const response = await fetch(apiUrl(path), options);
  if (!response.ok) throw new Error(`Request failed (${response.status})`);
  return response.json();
}
async function loadResults(id: string): Promise<void> {
  const data = await getJson(`results/${encodeURIComponent(id)}`);
  if (
    !Array.isArray(data) ||
    data.some(
      (row) =>
        typeof row?.observable !== "string" || typeof row?.type !== "string",
    )
  )
    throw new Error("Unexpected results format");
  rows.value = data as ObservableResult[];
  selected.value = window.matchMedia("(max-width: 1000px)").matches
    ? null
    : (rows.value[0] ?? null);
  engines.value = [
    ...new Set(
      rows.value.flatMap((row) => engineEntries(row).map(([name]) => name)),
    ),
  ];
  busy.value = false;
}
async function poll(id: string, started: number): Promise<void> {
  if (disposed) return;
  try {
    if (Date.now() - started > 10 * 60_000)
      throw new Error(
        "Analysis is taking longer than expected. Reload this page to check again.",
      );
    const status = asRecord(
      await getJson(`is_analysis_complete/${encodeURIComponent(id)}`),
    );
    if (status?.complete === true) await loadResults(id);
    else
      pollingTimer = setTimeout(() => {
        void poll(id, started);
      }, 1200);
  } catch (err) {
    error.value = err instanceof Error ? err.message : "Unable to load results";
    busy.value = false;
  }
}
async function start(): Promise<void> {
  error.value = "";
  if (demo) {
    view.value = "results";
    notify("Showing synthetic sample results. No external lookup was made.");
    return;
  }
  if (!rawInput.value.trim() || !chosenEngines.value.length) return;
  busy.value = true;
  try {
    const response = asRecord(
      await getJson("analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text: rawInput.value,
          engines: chosenEngines.value,
          ignore_cache: ignoreCache.value,
        }),
      }),
    );
    if (typeof response?.analysis_id !== "string")
      throw new Error("No analysis ID returned");
    analysisId.value = response.analysis_id;
    rows.value = [];
    selected.value = null;
    view.value = "results";
    const url = new URL(location.href);
    url.searchParams.set("analysis", analysisId.value);
    history.replaceState(null, "", url);
    await poll(analysisId.value, Date.now());
  } catch (err) {
    error.value = err instanceof Error ? err.message : "Analysis failed";
    busy.value = false;
  }
}
if (!demo && analysisId.value) {
  busy.value = true;
  void poll(analysisId.value, Date.now());
}
</script>

<template>
  <div
    class="workspace"
    :class="{ light: !dark }"
    @keydown.esc="
      selected = null;
      exporting = false;
      columnsOpen = false;
    "
  >
    <aside class="sidebar">
      <a
        class="brand"
        href="/ui"
        @click.prevent="view = rows.length ? 'results' : 'new'"
        ><span class="brand-mark"
          ><Shield :size="23" :stroke-width="1.7" /></span
        >cyberbro<span class="brand-dot">.</span></a
      >
      <div class="workspace-label">THREAT INTELLIGENCE</div>
      <button class="new-button" @click="view = 'new'">
        <Plus :size="17" /> New analysis <span>↗</span>
      </button>
      <div class="nav-caption">WORKSPACE</div>
      <nav aria-label="Main navigation">
        <button
          :class="{ active: view === 'results' }"
          @click="view = 'results'"
        >
          <LayoutDashboard :size="18" /> Overview
          <span v-if="rows.length" class="nav-count">{{ rows.length }}</span>
        </button>
        <a href="/history"
          ><History :size="18" /> Analysis history
          <ArrowUpRight :size="13" class="nav-arrow"
        /></a>
        <a href="/stats"
          ><Activity :size="18" /> Statistics
          <ArrowUpRight :size="13" class="nav-arrow"
        /></a>
      </nav>
      <div class="sidebar-bottom">
        <div class="local-instance">
          <span class="online-dot"></span>
          <div>
            {{ demo ? "Preview workspace" : "Local workspace"
            }}<small>{{
              demo ? "Synthetic data only" : "Powered by your Cyberbro API"
            }}</small>
          </div>
        </div>
        <a
          href="https://docs.cyberbro.net/"
          target="_blank"
          rel="noopener noreferrer"
          ><CircleHelp :size="17" /> Documentation <ArrowUpRight :size="14"
        /></a>
        <a
          href="https://github.com/stanfrbd/cyberbro"
          target="_blank"
          rel="noopener noreferrer"
          ><Box :size="17" /> Open source on GitHub <ArrowUpRight :size="14"
        /></a>
        <div class="sidebar-foot">
          <span>Built for the investigation.</span><Shield :size="13" />
        </div>
      </div>
    </aside>

    <div class="main-shell">
      <header class="topbar">
        <div class="breadcrumb">
          Workspace <ChevronRight :size="13" /><span>{{
            view === "new" ? "New analysis" : "Analysis overview"
          }}</span>
        </div>
        <div class="topbar-actions">
          <span v-if="demo" class="demo-badge"
            ><FlaskConical :size="13" /> DEMO DATA</span
          ><button
            class="icon-button"
            :aria-label="
              dark ? 'Switch to light theme' : 'Switch to dark theme'
            "
            @click="dark = !dark"
          >
            <Sun v-if="dark" :size="17" /><Moon v-else :size="17" /></button
          ><span class="avatar">CB</span>
        </div>
      </header>
      <main>
        <div v-if="error" role="alert" class="error-banner">
          <ShieldAlert :size="18" />{{ error
          }}<button
            class="icon-button"
            aria-label="Dismiss error"
            @click="error = ''"
          >
            <X :size="16" />
          </button>
        </div>
        <template v-if="view === 'results'">
          <div class="page-heading">
            <div>
              <div class="eyebrow">
                <span class="online-dot"></span> OBSERVABLE INTELLIGENCE
              </div>
              <h1>Investigation workspace</h1>
              <p>
                Less noise. More context. Explore what your observables reveal.
              </p>
            </div>
            <button class="button primary" @click="view = 'new'">
              <Plus :size="16" /> New analysis
            </button>
          </div>
          <div class="analysis-meta">
            <span class="analysis-tag"
              ><Fingerprint :size="14" />{{
                demo
                  ? "Sample investigation"
                  : analysisId || "No analysis selected"
              }}</span
            ><span
              ><Database :size="13" />{{
                demo
                  ? "Synthetic observables · no live reputation data"
                  : "Results from your configured engines"
              }}</span
            ><span class="analysis-status" v-if="rows.length"
              ><CheckCheck :size="14" /> Analysis complete</span
            >
          </div>
          <section class="metrics" aria-label="Analysis summary">
            <div class="metric">
              <div>
                <span>Total observables</span
                ><strong
                  >{{ rows.length }}<small>in this analysis</small></strong
                >
              </div>
              <Fingerprint />
            </div>
            <div class="metric">
              <div>
                <span>With source signals</span
                ><strong
                  >{{ signalsCount
                  }}<small class="amber-text">review recommended</small></strong
                >
              </div>
              <ShieldAlert class="amber-text" />
            </div>
            <div class="metric">
              <div>
                <span>Sources with data</span
                ><strong
                  >{{ sourceCount }}<small>returned information</small></strong
                >
              </div>
              <Layers />
            </div>
            <div class="metric">
              <div>
                <span>Not assessed</span
                ><strong
                  >{{ missingCount }}<small>no detection verdict</small></strong
                >
              </div>
              <CircleHelp />
            </div>
          </section>
          <section v-if="busy" class="loading-state" aria-live="polite">
            <LoaderCircle class="spin" :size="26" />
            <h2>Gathering intelligence</h2>
            <p>
              Your engines are working. Results will appear when the analysis
              completes.
            </p>
          </section>
          <section v-else-if="!rows.length" class="empty-state">
            <Search :size="28" />
            <h2>No observables to display</h2>
            <p>Start an analysis or open an existing analysis with its ID.</p>
            <button class="button primary" @click="view = 'new'">
              New analysis
            </button>
          </section>
          <div
            v-else
            class="results-layout"
            :class="{ 'detail-closed': !selected }"
          >
            <section class="results-panel">
              <div class="panel-heading">
                <div>
                  <h2>
                    Observables
                    <span class="count-pill">{{ rows.length }}</span>
                  </h2>
                  <p>Source evidence, ready to investigate.</p>
                </div>
                <div class="dropdown-anchor">
                  <button
                    class="button subtle"
                    :aria-expanded="exporting"
                    @click="
                      exporting = !exporting;
                      columnsOpen = false;
                    "
                  >
                    <ArrowDownToLine :size="15" /> Export
                    <ChevronDown :size="13" />
                  </button>
                  <div v-if="exporting" class="popover export-menu">
                    <small>EXPORT FILTERED RESULTS</small
                    ><button @click="download('csv')">Download CSV</button
                    ><button @click="download('json')">Download JSON</button
                    ><a
                      v-if="!demo && analysisId"
                      :href="`/export/${encodeURIComponent(analysisId)}?format=excel`"
                      >Full analysis Excel</a
                    >
                  </div>
                </div>
              </div>
              <div
                class="filter-tabs"
                role="group"
                aria-label="Filter by source signal"
              >
                <button
                  v-for="filter in filterTabs"
                  :key="filter.key"
                  :class="{ selected: activeFilter === filter.key }"
                  :aria-pressed="activeFilter === filter.key"
                  @click="activeFilter = filter.key"
                >
                  {{ filter.label
                  }}<span v-if="filter.key === 'all'">{{ rows.length }}</span
                  ><span v-if="filter.key === 'signals'" class="signal-count">{{
                    signalsCount
                  }}</span>
                </button>
              </div>
              <div class="table-toolbar">
                <label class="search-box"
                  ><Search :size="16" /><input
                    v-model="query"
                    aria-label="Search observables"
                    placeholder="Search observables, networks, context…" /></label
                ><label class="type-select"
                  ><ListFilter :size="14" /><select
                    v-model="typeFilter"
                    aria-label="Observable type"
                  >
                    <option>All types</option>
                    <option v-for="type in types" :key="type">
                      {{ type }}
                    </option>
                  </select></label
                >
                <div class="dropdown-anchor">
                  <button
                    class="icon-button bordered"
                    aria-label="Choose columns"
                    :aria-expanded="columnsOpen"
                    @click="
                      columnsOpen = !columnsOpen;
                      exporting = false;
                    "
                  >
                    <Settings2 :size="16" />
                  </button>
                  <div v-if="columnsOpen" class="popover column-menu">
                    <label
                      ><input
                        v-model="showNetwork"
                        type="checkbox"
                      />Network</label
                    ><label
                      ><input
                        v-model="showAbuse"
                        type="checkbox"
                      />AbuseIPDB</label
                    >
                  </div>
                </div>
              </div>
              <div class="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>OBSERVABLE</th>
                      <th>SOURCE SIGNALS</th>
                      <th>VIRUSTOTAL</th>
                      <th v-if="showAbuse">ABUSEIPDB</th>
                      <th v-if="showNetwork">NETWORK / CONTEXT</th>
                      <th aria-label="Open detail"></th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr
                      v-for="row in visible"
                      :key="row.observable + row.type"
                      :class="{ 'selected-row': selected === row }"
                    >
                      <td>
                        <button class="observable-cell" @click="choose(row)">
                          <span class="type-icon"
                            ><Globe2
                              v-if="row.type.includes('IP')"
                              :size="16" /><Fingerprint
                              v-else-if="
                                ['MD5', 'SHA1', 'SHA256'].includes(row.type)
                              "
                              :size="16" /><Network v-else :size="16" /></span
                          ><span
                            ><strong :title="row.observable">{{
                              row.observable
                            }}</strong
                            ><small>{{ row.type }}</small></span
                          >
                        </button>
                      </td>
                      <td>
                        <span class="status-badge" :class="signal(row)"
                          ><span></span>{{ signalLabel(signal(row)) }}</span
                        >
                      </td>
                      <td>
                        <span
                          v-if="asRecord(row.virustotal)"
                          class="detection"
                          :class="{
                            'has-detection':
                              Number(
                                asRecord(row.virustotal)?.total_malicious,
                              ) > 0,
                          }"
                          >{{
                            asRecord(row.virustotal)?.detection_ratio ?? "—"
                          }}</span
                        ><span v-else class="muted-value">No data</span>
                      </td>
                      <td v-if="showAbuse">
                        <div
                          v-if="
                            typeof asRecord(row.abuseipdb)
                              ?.abuseConfidenceScore === 'number'
                          "
                          class="abuse-cell"
                        >
                          <span
                            :class="{
                              'amber-text':
                                Number(
                                  asRecord(row.abuseipdb)?.abuseConfidenceScore,
                                ) > 0,
                            }"
                            >{{ asRecord(row.abuseipdb)?.abuseConfidenceScore
                            }}<small>%</small></span
                          >
                          <div class="abuse-track">
                            <i
                              :style="{
                                width: `${Math.min(100, Math.max(0, Number(asRecord(row.abuseipdb)?.abuseConfidenceScore)))}%`,
                              }"
                            ></i>
                          </div>
                        </div>
                        <span v-else class="muted-value">—</span>
                      </td>
                      <td v-if="showNetwork">
                        <span class="network-text">{{
                          context(row).network
                        }}</span
                        ><small class="country-text">{{
                          context(row).country
                        }}</small>
                      </td>
                      <td>
                        <button
                          class="icon-button row-action"
                          :aria-label="`Inspect ${row.observable}`"
                          @click="choose(row)"
                        >
                          <ChevronRight :size="15" />
                        </button>
                      </td>
                    </tr>
                    <tr v-if="!visible.length">
                      <td colspan="6" class="no-matches">
                        No matching observables. Try another search or filter.
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <div class="table-footer">
                <span
                  >Showing
                  <strong
                    >{{ filtered.length ? (page - 1) * pageSize + 1 : 0 }}–{{
                      Math.min(page * pageSize, filtered.length)
                    }}</strong
                  >
                  of {{ filtered.length }} observables</span
                >
                <div>
                  <button
                    class="icon-button bordered"
                    aria-label="Previous page"
                    :disabled="page <= 1"
                    @click="page--"
                  >
                    <ArrowLeft :size="14" /></button
                  ><span class="page-index">{{ page }} / {{ pageCount }}</span
                  ><button
                    class="icon-button bordered"
                    aria-label="Next page"
                    :disabled="page >= pageCount"
                    @click="page++"
                  >
                    <ArrowRight :size="14" />
                  </button>
                </div>
              </div>
              <div class="evidence-note">
                <Shield :size="13" />Source signals are evidence, not a safety
                verdict. No data does not mean safe.
              </div>
            </section>
            <aside
              v-if="selected"
              class="detail-panel"
              aria-label="Observable details"
            >
              <div class="detail-top">
                <span>OBSERVABLE DETAILS</span
                ><button
                  class="icon-button"
                  aria-label="Close details"
                  @click="selected = null"
                >
                  <X :size="16" />
                </button>
              </div>
              <div class="detail-identity">
                <div class="detail-icon"><Fingerprint :size="23" /></div>
                <span class="type-chip">{{ selected.type }}</span>
                <h2>{{ selected.observable }}</h2>
                <span class="status-badge" :class="signal(selected)"
                  ><span></span>{{ signalLabel(signal(selected)) }}</span
                ><button class="copy-button" @click="copy(selected.observable)">
                  <Copy :size="13" />Copy observable
                </button>
              </div>
              <div class="detail-tabs">
                <button
                  :class="{ active: tab === 'overview' }"
                  @click="tab = 'overview'"
                >
                  Overview</button
                ><button
                  :class="{ active: tab === 'json' }"
                  @click="tab = 'json'"
                >
                  <FileJson :size="14" />Raw JSON
                </button>
              </div>
              <div v-if="tab === 'overview'" class="detail-content">
                <div class="context-heading">
                  <h3>Source evidence</h3>
                  <span>{{ detailEntries.length }} sources</span>
                </div>
                <div
                  v-for="[name, value] in detailEntries"
                  :key="name"
                  class="source-card"
                >
                  <div class="source-title">
                    <span class="source-logo">{{
                      engineLabel(name).slice(0, 2).toUpperCase()
                    }}</span
                    ><strong>{{ engineLabel(name) }}</strong
                    ><Check
                      v-if="value && !value.error"
                      :size="14"
                      class="mint-text"
                    /><CircleHelp v-else :size="14" class="muted-value" />
                  </div>
                  <div v-if="name === 'virustotal' && value" class="vt-summary">
                    <strong
                      :class="{
                        'amber-text': Number(value.total_malicious) > 0,
                      }"
                      >{{ value.detection_ratio ?? "—" }}</strong
                    ><span>engines flagged this observable</span>
                  </div>
                  <div
                    v-else-if="name === 'abuseipdb' && value"
                    class="source-fields"
                  >
                    <span
                      >Abuse confidence<strong
                        >{{ value.abuseConfidenceScore ?? "—" }}%</strong
                      ></span
                    ><span v-if="value.totalReports !== undefined"
                      >Reports<strong>{{ value.totalReports }}</strong></span
                    >
                  </div>
                  <div
                    v-else-if="name === 'ipinfo' && value"
                    class="source-fields"
                  >
                    <span
                      >Network<strong>{{ value.asn }}</strong></span
                    ><span
                      >Country<strong>{{ value.country_name }}</strong></span
                    >
                  </div>
                  <div v-else-if="!value || value.error" class="source-empty">
                    {{ sourceStatus(value) }}
                  </div>
                  <template v-else
                    ><details class="source-raw">
                      <summary>
                        View response <ChevronDown :size="12" />
                      </summary>
                      <pre>{{ JSON.stringify(value, null, 2) }}</pre>
                    </details></template
                  ><a
                    v-if="value && safeLink(value.link)"
                    :href="safeLink(value.link)"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="source-link"
                    >Open source report <ExternalLink :size="11"
                  /></a>
                </div>
              </div>
              <div v-else class="json-panel">
                <button
                  class="button subtle"
                  @click="copy(JSON.stringify(selected, null, 2))"
                >
                  <Copy :size="13" />Copy JSON
                </button>
                <pre>{{ JSON.stringify(selected, null, 2) }}</pre>
              </div>
            </aside>
          </div>
          <div class="workspace-footer">
            <span
              ><Shield :size="12" />Cyberbro · Open-source observable
              intelligence</span
            ><a
              v-if="!demo && analysisId"
              :href="`/results/${encodeURIComponent(analysisId)}`"
              >Open classic results <ArrowUpRight :size="12" /></a
            ><span v-else>Interface preview / synthetic dataset</span>
          </div>
        </template>

        <template v-else>
          <div class="page-heading">
            <div>
              <div class="eyebrow">
                <span class="online-dot"></span> START WITH WHAT YOU HAVE
              </div>
              <h1>A little input. A lot of context.</h1>
              <p>
                Paste observables or raw logs. Cyberbro handles the extraction.
              </p>
            </div>
            <button
              v-if="rows.length"
              class="button subtle"
              @click="view = 'results'"
            >
              <ArrowLeft :size="15" />Back to results
            </button>
          </div>
          <form class="analysis-form" @submit.prevent="start">
            <section class="input-panel">
              <div class="panel-heading">
                <h2>Your input</h2>
                <span class="muted-value"
                  >IPs · domains · URLs · hashes · extensions</span
                >
              </div>
              <textarea
                v-model="rawInput"
                :required="!demo"
                aria-label="Observables to analyze"
                placeholder="Paste your observables, logs, email headers, or any messy text here…"
              />
              <div class="input-bottom">
                <span
                  ><Shield :size="13" />Submitted to the engines you select
                  below.</span
                ><span>{{ rawInput.length.toLocaleString() }} characters</span>
              </div>
            </section>
            <section class="engine-panel">
              <div class="panel-heading">
                <div>
                  <h2>
                    Analysis engines
                    <span class="count-pill"
                      >{{ chosenEngines.length }} selected</span
                    >
                  </h2>
                  <p>Choose the sources that matter to your investigation.</p>
                </div>
                <label class="search-box"
                  ><Search :size="15" /><input
                    v-model="engineQuery"
                    aria-label="Search engines"
                    placeholder="Find an engine…"
                /></label>
              </div>
              <div class="engine-presets">
                <button
                  type="button"
                  class="button subtle"
                  @click="
                    chosenEngines = availableEngines.filter((name) =>
                      ['reverse_dns', 'rdap_whois'].includes(name),
                    )
                  "
                >
                  Basic lookup</button
                ><button
                  type="button"
                  class="button subtle"
                  @click="chosenEngines = [...availableEngines]"
                >
                  Select all</button
                ><button
                  type="button"
                  class="button subtle"
                  @click="chosenEngines = []"
                >
                  Clear
                </button>
              </div>
              <div class="engine-grid">
                <button
                  v-for="name in filteredEngines"
                  :key="name"
                  type="button"
                  class="engine-choice"
                  :class="{ chosen: chosenEngines.includes(name) }"
                  :aria-pressed="chosenEngines.includes(name)"
                  @click="toggleEngine(name)"
                >
                  <span class="source-logo">{{
                    engineLabel(name).slice(0, 2).toUpperCase()
                  }}</span
                  ><span
                    >{{ engineLabel(name)
                    }}<small>{{
                      ["reverse_dns", "rdap_whois"].includes(name)
                        ? "Basic enrichment"
                        : "Uses instance configuration"
                    }}</small></span
                  ><span class="check-box"
                    ><Check v-if="chosenEngines.includes(name)" :size="12"
                  /></span>
                </button>
              </div>
              <p v-if="!availableEngines.length" class="muted-value">
                Open this interface through /ui on your Cyberbro instance, or
                use ?demo=1 to explore sample data.
              </p>
              <div class="form-footer">
                <label
                  ><input v-model="ignoreCache" type="checkbox" />Ignore cached
                  results</label
                ><button
                  class="button primary"
                  type="submit"
                  :disabled="
                    busy ||
                    (!demo && (!chosenEngines.length || !rawInput.trim()))
                  "
                >
                  <LoaderCircle v-if="busy" :size="15" class="spin" /><Search
                    v-else
                    :size="15"
                  />{{ demo ? "Explore sample results" : "Start analysis"
                  }}<ArrowRight :size="15" />
                </button>
              </div>
              <div v-if="demo" class="demo-note">
                <FlaskConical :size="15" />Preview mode uses synthetic results.
                It does not analyze the text you enter.
              </div>
            </section>
          </form>
        </template>
      </main>
    </div>
    <div v-if="toast" role="status" class="toast">
      <Check :size="16" />{{ toast }}
    </div>
  </div>
</template>
