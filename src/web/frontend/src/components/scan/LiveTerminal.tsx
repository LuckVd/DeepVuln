import { useEffect, useRef, useState, useCallback, memo } from 'react';
import { Badge, Card, Collapsible, CollapsibleTrigger, CollapsibleContent } from '@/components/ui';
import { Terminal, ChevronDown, ChevronRight, Wifi, WifiOff, Loader2, Maximize2, Minimize2 } from 'lucide-react';
import { getWebSocketClient } from '@/api/websocket';
import { scansApi } from '@/api/scans';
import { formatDuration } from '@/utils/format';
import type { ConnectionState } from '@/types/websocket';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type LogType = 'info' | 'success' | 'warning' | 'error' | 'phase' | 'finding' | 'debate' | 'adjudication' | 'verification' | 'skip';

interface LogEntry {
  id: string;
  timestamp: string;
  message: string;
  type: LogType;
  detail?: Record<string, any>;
  expanded?: boolean;
}

interface LiveTerminalProps {
  scanId: number;
  scanStatus: string | null;
  wsState: ConnectionState;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_LOGS = 500;
const PROGRESS_THROTTLE_MS = 500;

const PHASE_LABELS: Record<string, string> = {
  l1_preparation: 'L1 准备',
  source_preparation: '源码准备',
  engine_selection: '引擎选择',
  engine_execution: '引擎执行',
  l1_attack_surface: '攻击面分析',
  L1_preparation: 'L1 准备',
  L1_attack_surface: 'L1 攻击面',
  L2_semgrep: 'Semgrep',
  L2_codeql: 'CodeQL',
  L3_agent: 'Agent 审计',
  L3_adjudication: '裁决',
  result_merging: '结果合并',
  token_statistics: 'Token 统计',
  exploitability_verification: '可利用性验证',
  deduplication_adjudication: '去重裁决',
  adversarial_verification: '对抗性验证',
  report_generation: '报告生成',
};

// Phase descriptions for more informative logs
const PHASE_DESC: Record<string, string> = {
  l1_preparation: '检测技术栈、框架、识别攻击面...',
  source_preparation: '索引源代码文件...',
  engine_selection: '根据技术栈选择扫描引擎...',
  engine_execution: '运行静态分析和 LLM 审计...',
  l1_attack_surface: '分析入口点和攻击向量...',
  L1_preparation: '检测技术栈、框架、识别攻击面...',
  L1_attack_surface: '分析入口点和攻击向量...',
  L2_semgrep: 'Semgrep 静态规则扫描...',
  L2_codeql: 'CodeQL 数据流分析...',
  L3_agent: 'LLM Agent 逐文件深度审计...',
  L3_adjudication: '多引擎结果裁决...',
  result_merging: '合并去重各引擎结果...',
  token_statistics: '统计 Token 使用和成本...',
  exploitability_verification: '验证漏洞可利用性...',
  deduplication_adjudication: '跨引擎结果去重...',
  adversarial_verification: '对抗性辩论验证漏洞真实性...',
  report_generation: '生成扫描报告...',
};

const SEVERITY_ICONS: Record<string, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🟢',
  info: '🔵',
};

const ROLE_LABELS: Record<string, string> = {
  attacker: '🔴 攻击方',
  defender: '🟢 防御方',
  judge: '⚖️ 裁判',
  critic: '🟣 评论员',
  verifier: '🔵 验证者',
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let logIdCounter = 0;
function nextLogId(): string {
  return `log-${++logIdCounter}`;
}

function timeStr(): string {
  return new Date().toLocaleTimeString('zh-CN', { hour12: false });
}

function phaseLabel(phase: string): string {
  return PHASE_LABELS[phase] || phase;
}

function logColor(type: LogType): string {
  switch (type) {
    case 'success': return 'text-emerald-400';
    case 'error': return 'text-red-400';
    case 'warning': return 'text-amber-400';
    case 'phase': return 'text-cyan-400';
    case 'finding': return 'text-fuchsia-400';
    case 'debate': return 'text-purple-400';
    case 'adjudication': return 'text-blue-400';
    case 'verification': return 'text-teal-400';
    case 'skip': return 'text-slate-500';
    default: return 'text-slate-400';
  }
}

/**
 * Format phase_complete result data into detailed terminal lines.
 */
function formatPhaseResult(phase: string, d: Record<string, any>): string[] {
  const lines: string[] = [];

  switch (phase) {
    case 'l1_preparation':
    case 'L1_preparation':
      if (d.languages && Array.isArray(d.languages) && d.languages.length > 0) {
        lines.push(`  语言: ${d.languages.join(', ')}`);
      }
      if (d.primary_language) {
        lines.push(`  主语言: ${d.primary_language}`);
      }
      if (d.frameworks && Array.isArray(d.frameworks) && d.frameworks.length > 0) {
        lines.push(`  框架: ${d.frameworks.join(', ')}`);
      }
      if (d.total_files) {
        lines.push(`  项目文件: ${d.total_files} 个`);
      }
      if (d.file_counts && typeof d.file_counts === 'object') {
        const details = Object.entries(d.file_counts)
          .map(([lang, count]) => `${lang}(${count})`)
          .join(', ');
        if (details) lines.push(`  文件分布: ${details}`);
      }
      if (d.attack_surface) {
        if (typeof d.attack_surface === 'object') {
          const count = d.attack_surface.total_endpoints ?? d.attack_surface.total ?? d.attack_surface.count ?? '?';
          lines.push(`  攻击面入口点: ${count}`);
        } else {
          lines.push(`  攻击面入口点: ${d.attack_surface}`);
        }
      }
      break;

    case 'source_preparation':
      if (d.total_files) lines.push(`  索引文件: ${d.total_files} 个`);
      break;

    case 'engine_selection':
      if (d.engines) {
        const list = Array.isArray(d.engines) ? d.engines.join(', ') : d.engines;
        lines.push(`  选用引擎: ${list}`);
      }
      break;

    case 'engine_execution':
      if (d.findings) lines.push(`  发现漏洞: ${d.findings} 个`);
      // Per-engine details
      if (d.per_engine_details && typeof d.per_engine_details === 'object') {
        for (const [engine, info] of Object.entries(d.per_engine_details) as [string, any][]) {
          const dur = info.duration_seconds > 0 ? formatDuration(info.duration_seconds) : '0秒';
          const tok = info.tokens_used > 0 ? `, ${info.tokens_used.toLocaleString()} tokens` : '';
          lines.push(`    ${engine.toUpperCase()}: ${info.findings} 漏洞, ${dur}${tok}`);
        }
      }
      break;

    case 'deduplication_adjudication':
      if (d.unique_findings !== undefined) lines.push(`  去重后: ${d.unique_findings} 个唯一漏洞`);
      if (d.duplicates_removed !== undefined) lines.push(`  移除重复: ${d.duplicates_removed} 个`);
      break;

    case 'adversarial_verification':
      if (d.verified_findings !== undefined) lines.push(`  已验证: ${d.verified_findings} 个`);
      if (d.confirmed !== undefined) lines.push(`  确认: ${d.confirmed} | 驳回: ${d.rejected ?? 0}`);
      break;

    case 'result_merging':
      if (d.total_findings !== undefined) lines.push(`  最终漏洞: ${d.total_findings} 个`);
      break;

    case 'token_statistics':
      if (d.total_tokens !== undefined) lines.push(`  总 Token: ${d.total_tokens.toLocaleString()}`);
      if (d.estimated_cost !== undefined) lines.push(`  预估成本: $${Number(d.estimated_cost).toFixed(4)}`);
      break;
  }

  return lines;
}

/**
 * Format a debate round event into detailed log lines.
 */
function formatDebateRound(d: Record<string, any>): string[] {
  const lines: string[] = [];
  const role = d.role || 'unknown';
  const roleLabel = ROLE_LABELS[role] || role;
  const findingTitle = d.finding_title || d.vuln_type || `Finding #${d.finding_id}`;
  const roundInfo = d.total_rounds ? ` [${d.round}/${d.total_rounds}]` : ` [R${d.round}]`;
  const confidence = d.confidence !== undefined ? ` (${(d.confidence * 100).toFixed(0)}%)` : '';

  // Header line
  if (role === 'judge') {
    const verdict = d.verdict ? ` → ${d.verdict}` : '';
    lines.push(`  ${roleLabel}${roundInfo} ${findingTitle}${confidence}${verdict}`);
  } else {
    const strength = d.strength ? ` [${d.strength}]` : '';
    lines.push(`  ${roleLabel}${roundInfo} ${findingTitle}${confidence}${strength}`);
  }

  // Claim / main content
  const claim = d.claim || d.content || '';
  if (claim) {
    const truncated = claim.length > 300 ? claim.slice(0, 300) + '...' : claim;
    lines.push(`    ${truncated}`);
  }

  // Evidence (brief, from top-level field)
  if (d.evidence) {
    const ev = typeof d.evidence === 'string'
      ? (d.evidence.length > 200 ? d.evidence.slice(0, 200) + '...' : d.evidence)
      : `${d.evidence.length} 条证据`;
    lines.push(`    证据: ${ev}`);
  }

  // Judge recommendation
  if (d.recommended_action) {
    lines.push(`    建议: ${d.recommended_action}`);
  }

  return lines;
}

// ---------------------------------------------------------------------------
// DetailCard - expandable detail panel for enriched events
// ---------------------------------------------------------------------------

function DetailCard({ data, type }: { data: Record<string, any>; type: LogType }) {
  const labelCls = 'text-slate-500 font-mono text-xs';
  const valueCls = 'text-slate-300 font-mono text-xs whitespace-pre-wrap break-all';

  const renderList = (items: any[] | undefined, fallback = '无') => {
    if (!items || !Array.isArray(items) || items.length === 0) return fallback;
    return items.map((item, i) => (
      <div key={i} className="ml-2">• {String(item).length > 500 ? String(item).slice(0, 500) + '...' : String(item)}</div>
    ));
  };

  // Debate detail (attacker / defender / judge)
  if (type === 'debate') {
    return (
      <div className="ml-6 my-1 p-2 rounded border border-slate-800 bg-slate-900/60 space-y-1.5 max-w-full">
        {data.evidence && Array.isArray(data.evidence) && data.evidence.length > 0 && (
          <div><span className={labelCls}>证据 ({data.evidence.length} 条):</span><div className={valueCls}>{renderList(data.evidence)}</div></div>
        )}
        {data.reasoning && <div><span className={labelCls}>推理:</span><div className={valueCls}>{data.reasoning}</div></div>}
        {data.poc_code && <div><span className={labelCls}>PoC:</span><div className={`${valueCls} text-red-300`}><code className="text-xs">{data.poc_code}</code></div></div>}
        {data.exploitation_steps && Array.isArray(data.exploitation_steps) && data.exploitation_steps.length > 0 && (
          <div><span className={labelCls}>利用步骤:</span><div className={valueCls}>{renderList(data.exploitation_steps)}</div></div>
        )}
        {data.prerequisites && Array.isArray(data.prerequisites) && data.prerequisites.length > 0 && (
          <div><span className={labelCls}>前提条件:</span><div className={valueCls}>{renderList(data.prerequisites)}</div></div>
        )}
        {data.counter_arguments && Array.isArray(data.counter_arguments) && data.counter_arguments.length > 0 && (
          <div><span className={labelCls}>反驳论点:</span><div className={valueCls}>{renderList(data.counter_arguments)}</div></div>
        )}
        {data.sanitizers_found && Array.isArray(data.sanitizers_found) && data.sanitizers_found.length > 0 && (
          <div><span className={labelCls}>发现的净化器:</span><div className={`${valueCls} text-emerald-300`}>{renderList(data.sanitizers_found)}</div></div>
        )}
        {data.validation_checks && Array.isArray(data.validation_checks) && data.validation_checks.length > 0 && (
          <div><span className={labelCls}>验证检查:</span><div className={`${valueCls} text-emerald-300`}>{renderList(data.validation_checks)}</div></div>
        )}
        {data.framework_protections && Array.isArray(data.framework_protections) && data.framework_protections.length > 0 && (
          <div><span className={labelCls}>框架保护:</span><div className={`${valueCls} text-emerald-300`}>{renderList(data.framework_protections)}</div></div>
        )}
        {data.false_positive_reasons && Array.isArray(data.false_positive_reasons) && data.false_positive_reasons.length > 0 && (
          <div><span className={labelCls}>误报理由:</span><div className={valueCls}>{renderList(data.false_positive_reasons)}</div></div>
        )}
        {data.exploitation_barriers && Array.isArray(data.exploitation_barriers) && data.exploitation_barriers.length > 0 && (
          <div><span className={labelCls}>利用障碍:</span><div className={valueCls}>{renderList(data.exploitation_barriers)}</div></div>
        )}
        {data.summary && <div><span className={labelCls}>总结:</span><div className={valueCls}>{data.summary}</div></div>}
        {data.key_factors && Array.isArray(data.key_factors) && data.key_factors.length > 0 && (
          <div><span className={labelCls}>关键因素:</span><div className={valueCls}>{renderList(data.key_factors)}</div></div>
        )}
        {data.conditions && Array.isArray(data.conditions) && data.conditions.length > 0 && (
          <div><span className={labelCls}>条件:</span><div className={valueCls}>{renderList(data.conditions)}</div></div>
        )}
        {(data.attacker_strength !== undefined || data.defender_strength !== undefined) && (
          <div className="flex gap-4">
            {data.attacker_strength !== undefined && <span className={labelCls}>攻击方强度: <span className="text-red-300">{data.attacker_strength}</span></span>}
            {data.defender_strength !== undefined && <span className={labelCls}>防御方强度: <span className="text-emerald-300">{data.defender_strength}</span></span>}
          </div>
        )}
        {data.is_rebuttal && <span className="text-xs text-slate-600 font-mono">↩ 反驳轮次</span>}
      </div>
    );
  }

  // Adjudication result detail
  if (type === 'adjudication') {
    return (
      <div className="ml-6 my-1 p-2 rounded border border-slate-800 bg-slate-900/60 space-y-1">
        <div className="flex flex-wrap gap-3">
          {data.final_status && <span className={labelCls}>最终状态: <span className="text-amber-300">{data.final_status}</span></span>}
          {data.report_status && <span className={labelCls}>报告状态: <span className="text-slate-300">{data.report_status}</span></span>}
          {data.evidence_strength && <span className={labelCls}>证据强度: <span className="text-slate-300">{data.evidence_strength}</span></span>}
        </div>
        {data.override_applied && <span className="text-xs text-amber-400 font-mono">⚠ 覆盖已应用</span>}
        {data.override_reason && <div><span className={labelCls}>覆盖原因:</span><div className={valueCls}>{data.override_reason}</div></div>}
      </div>
    );
  }

  // Verification result detail
  if (type === 'verification') {
    return (
      <div className="ml-6 my-1 p-2 rounded border border-slate-800 bg-slate-900/60 space-y-1">
        <div className="flex gap-3">
          {data.status && <span className={labelCls}>可利用性: <span className="text-amber-300">{data.status}</span></span>}
          {data.confidence !== undefined && <span className={labelCls}>置信度: {(data.confidence * 100).toFixed(0)}%</span>}
        </div>
        {data.reasoning && <div><span className={labelCls}>推理:</span><div className={valueCls}>{data.reasoning}</div></div>}
      </div>
    );
  }

  return null;
}

// ---------------------------------------------------------------------------
// Single log line (memo'd) with expandable detail support
// ---------------------------------------------------------------------------

const LogLine = memo(function LogLine({ entry, onToggle }: { entry: LogEntry; onToggle: (id: string) => void }) {
  const hasDetail = !!entry.detail;
  return (
    <div>
      <div
        className={`flex items-start gap-3 hover:bg-white/[0.03] px-2 py-0.5 transition-colors rounded ${hasDetail ? 'cursor-pointer' : ''}`}
        onClick={() => hasDetail && onToggle(entry.id)}
      >
        <span className="text-slate-600 text-xs flex-shrink-0 w-20 font-mono select-none">
          {entry.timestamp}
        </span>
        {hasDetail ? (
          <ChevronRight className={`h-3.5 w-3.5 mt-0.5 flex-shrink-0 text-slate-500 transition-transform ${entry.expanded ? 'rotate-90' : ''}`} />
        ) : (
          <span className="w-3.5 flex-shrink-0" />
        )}
        <span className={`${logColor(entry.type)} flex-1 font-mono text-sm whitespace-pre-wrap break-all`}>
          {entry.message}
        </span>
      </div>
      {hasDetail && entry.expanded && (
        <DetailCard data={entry.detail!} type={entry.type} />
      )}
    </div>
  );
});

// ---------------------------------------------------------------------------
// Connection indicator
// ---------------------------------------------------------------------------

function ConnectionDot({ state }: { state: ConnectionState }) {
  if (state === 'connected') {
    return (
      <span className="flex items-center gap-1.5 text-emerald-400 text-xs font-mono">
        <Wifi className="h-3.5 w-3.5" />
        LIVE
      </span>
    );
  }
  if (state === 'connecting') {
    return (
      <span className="flex items-center gap-1.5 text-amber-400 text-xs font-mono">
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
        CONNECTING
      </span>
    );
  }
  return (
    <span className="flex items-center gap-1.5 text-slate-500 text-xs font-mono">
      <WifiOff className="h-3.5 w-3.5" />
      POLLING
    </span>
  );
}

// ---------------------------------------------------------------------------
// LiveTerminal
// ---------------------------------------------------------------------------

const LiveTerminalInner = memo(function LiveTerminalInner({ scanId, scanStatus, wsState }: LiveTerminalProps) {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isOpen, setIsOpen] = useState(true);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const cardRef = useRef<HTMLDivElement>(null);
  const autoScrollRef = useRef(true);
  const lastProgressRef = useRef<number>(0);

  // --- auto-scroll ---
  useEffect(() => {
    if (autoScrollRef.current && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs]);

  const handleScroll = useCallback(() => {
    const el = containerRef.current;
    if (!el) return;
    autoScrollRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 60;
  }, []);

  // --- toggle detail expansion ---
  const toggleDetail = useCallback((id: string) => {
    setLogs(prev => prev.map(l => l.id === id ? { ...l, expanded: !l.expanded } : l));
  }, []);

  // --- add log helper (with optional detail) ---
  const addLog = useCallback((message: string, type: LogType = 'info', detail?: Record<string, any>) => {
    setLogs(prev => {
      const next = [...prev, { id: nextLogId(), timestamp: timeStr(), message, type, detail }];
      return next.length > MAX_LOGS ? next.slice(-MAX_LOGS) : next;
    });
  }, []);

  // --- subscribe to WS events ---
  useEffect(() => {
    const client = getWebSocketClient();
    const unsubs: (() => void)[] = [];

    // ─── phase_start ───
    unsubs.push(
      client.on('phase_start', (event: any) => {
        const d = event.data;
        if (!d?.phase) return;
        const desc = PHASE_DESC[d.phase] || '';
        addLog(`▸ 阶段开始: ${phaseLabel(d.phase)}`, 'phase');
        if (desc) addLog(`  ${desc}`, 'phase');
      }),
    );

    // ─── phase_complete (enhanced with result data) ───
    unsubs.push(
      client.on('phase_complete', (event: any) => {
        const d = event.data;
        if (!d?.phase) return;
        const dur = d.duration_seconds > 0 ? formatDuration(d.duration_seconds) : '0秒';
        const findStr = d.findings > 0 ? ` | 发现 ${d.findings} 个漏洞` : '';
        addLog(`✓ 阶段完成: ${phaseLabel(d.phase)} (${dur}${findStr})`, 'success');
        // Detailed result lines
        const details = formatPhaseResult(d.phase, d);
        for (const line of details) {
          addLog(line, 'info');
        }
      }),
    );

    // ─── finding_new (enhanced with full details) ───
    unsubs.push(
      client.on('finding_new', (event: any) => {
        const d = event.data;
        if (!d) return;
        const sev = (d.severity || 'info').toLowerCase();
        const icon = SEVERITY_ICONS[sev] || '⚪';
        const title = d.title || d.vuln_type || '未知漏洞';
        const engine = d.engine ? ` [${d.engine}]` : '';
        const location = d.file_path ? `${d.file_path}:${d.line_start || '?'}` : '';

        addLog(
          `${icon} [${sev.toUpperCase()}] ${title}${engine}`,
          'finding',
        );
        if (location) {
          addLog(`    ${location}`, 'info');
        }
        if (d.description && d.description.length > 0) {
          const desc = d.description.length > 150 ? d.description.slice(0, 150) + '...' : d.description;
          addLog(`    ${desc}`, 'info');
        }
      }),
    );

    // ─── progress (engine messages, file progress) ───
    unsubs.push(
      client.on('progress', (event: any) => {
        const d = event.data;
        if (!d?.message) return;
        const now = Date.now();
        if (now - lastProgressRef.current < PROGRESS_THROTTLE_MS) return;
        lastProgressRef.current = now;

        const msg = d.message as string;
        // Parse engine start/complete messages for richer display
        if (msg.includes('Running') && msg.includes('analysis')) {
          const match = msg.match(/Running\s+(\w+)\s+analysis/i);
          if (match) {
            addLog(`⚙ 启动引擎: ${match[1].toUpperCase()}`, 'info');
            return;
          }
        }
        if (msg.includes('analysis complete')) {
          const match = msg.match(/(\w+)\s+analysis complete:\s+(\d+)\s+findings/i);
          if (match) {
            addLog(`✦ ${match[1].toUpperCase()} 完成: ${match[2]} 个漏洞`, 'success');
            return;
          }
        }
        if (msg.includes('analysis failed')) {
          addLog(`✗ ${msg}`, 'error');
          return;
        }
        addLog(`  ${msg}`, 'info');
      }),
    );

    // ─── adversarial_round (detailed debate display with expandable detail) ───
    unsubs.push(
      client.on('adversarial_round', (event: any) => {
        const d = event.data;
        if (!d) return;
        const findingTitle = d.finding_title || d.vuln_type || `Finding #${d.finding_id}`;
        const role = d.role || 'unknown';
        const roundNum = d.round || '?';

        // First line: finding + round header (only for attacker role to avoid repetition)
        if (role === 'attacker') {
          addLog(`\n🗣 辩论漏洞: ${findingTitle} (${d.severity || ''})`, 'debate');
        }

        // Format the detailed debate round
        const lines = formatDebateRound(d);
        for (let i = 0; i < lines.length; i++) {
          // Only attach detail to the first line (the role header line)
          const detail = (i === 0 && d.detail) ? d.detail : undefined;
          addLog(lines[i], 'debate', detail);
        }
      }),
    );

    // ─── warning ───
    unsubs.push(
      client.on('warning', (event: any) => {
        addLog(`⚠ ${event.data?.message || '警告'}`, 'warning');
      }),
    );

    // ─── adjudication_result ───
    unsubs.push(
      client.on('adjudication_result', (event: any) => {
        const d = event.data;
        if (!d) return;
        const icon = d.final_status === 'confirmed' ? '✓' : d.final_status === 'false_positive' ? '✗' : '?';
        const statusMap: Record<string, string> = {
          confirmed: '已确认', false_positive: '误报', conditional: '有条件',
          not_exploitable: '不可利用', informational: '信息级',
        };
        const statusLabel = statusMap[d.final_status] || d.final_status;
        addLog(`  ${icon} 裁决: ${d.finding_title || '未知'} → ${statusLabel}`, 'adjudication', d);
      }),
    );

    // ─── verification_result ───
    unsubs.push(
      client.on('verification_result', (event: any) => {
        const d = event.data;
        if (!d) return;
        const statusMap: Record<string, string> = {
          confirmed: '已确认', false_positive: '误报', needs_review: '待审查',
          conditional: '有条件', not_exploitable: '不可利用',
        };
        const statusLabel = statusMap[d.status] || d.status;
        const confidence = d.confidence !== undefined ? ` (${(d.confidence * 100).toFixed(0)}%)` : '';
        addLog(`  🔍 验证: ${d.finding_title || '未知'} → ${statusLabel}${confidence}`, 'verification', d);
      }),
    );

    // ─── finding_skipped ───
    unsubs.push(
      client.on('finding_skipped', (event: any) => {
        const d = event.data;
        if (!d) return;
        addLog(`  ⏭ 跳过: ${d.finding_title || '未知'} (${d.reason || '未满足验证条件'})`, 'skip');
      }),
    );

    // ─── scan_complete (enhanced with severity breakdown) ───
    unsubs.push(
      client.on('scan_complete', (event: any) => {
        const d = event.data;
        if (!d) return;
        const dur = d.duration_seconds > 0 ? formatDuration(d.duration_seconds) : '0秒';
        const tokens = d.tokens_used > 0 ? d.tokens_used.toLocaleString() : '?';
        addLog('', 'info'); // blank line
        addLog(`══════════════════════════════════════════════`, 'success');
        addLog(`  ✓ 扫描完成`, 'success');
        addLog(`  耗时: ${dur}`, 'success');
        addLog(`  漏洞: ${d.findings_count} 个`, 'success');
        addLog(`  Token: ${tokens}`, 'success');

        // Severity breakdown
        if (d.severity_breakdown) {
          const sb = d.severity_breakdown;
          addLog(`  严重性分布: 🔴${sb.critical ?? 0} 🟠${sb.high ?? 0} 🟡${sb.medium ?? 0} 🟢${sb.low ?? 0} 🔵${sb.info ?? 0}`, 'info');
          if (sb.false_positive && sb.false_positive > 0) {
            addLog(`  误报: ${sb.false_positive} 个`, 'info');
          }
        }

        // Per-phase tokens
        if (d.per_phase_tokens) {
          const pt = d.per_phase_tokens;
          const parts: string[] = [];
          if (pt.agent_scan) parts.push(`Agent ${pt.agent_scan.toLocaleString()}`);
          if (pt.adversarial) parts.push(`对抗验证 ${pt.adversarial.toLocaleString()}`);
          if (pt.total) parts.push(`总计 ${pt.total.toLocaleString()}`);
          if (parts.length > 0) {
            addLog(`  Token 明细: ${parts.join(' | ')}`, 'info');
          }
        }

        addLog(`══════════════════════════════════════════════`, 'success');
      }),
    );

    // ─── scan_failed ───
    unsubs.push(
      client.on('scan_failed', (event: any) => {
        addLog(`\n✗ 扫描失败: ${event.data?.error || '未知错误'}`, 'error');
      }),
    );

    // ─── scan_paused ───
    unsubs.push(
      client.on('scan_paused', () => {
        addLog(`⏸ 扫描已暂停`, 'warning');
      }),
    );

    return () => unsubs.forEach(fn => fn());
  }, [addLog]);

  // --- initial log / load historical events for completed scans ---
  const historyLoadedRef = useRef(false);
  useEffect(() => {
    if (!scanStatus) return;

    // Running scan: just show initial status
    if (scanStatus === 'running' || scanStatus === 'pending') {
      if (logs.length === 0) {
        addLog(`◉ 扫描 #${scanId} 进行中...`, 'phase');
      }
      return;
    }

    if (scanStatus === 'paused') {
      addLog(`◉ 扫描 #${scanId} 已暂停`, 'warning');
      return;
    }

    // Terminal states (completed/failed/cancelled): load history once
    if (historyLoadedRef.current) return;
    historyLoadedRef.current = true;

    const loadHistory = async () => {
      try {
        const resp = await scansApi.getEvents(scanId, { page_size: 500 });
        const events = resp.events || [];
        if (events.length > 0) {
          // Convert DB events to terminal logs
          for (const ev of events) {
            const ts = ev.created_at
              ? new Date(ev.created_at).toLocaleTimeString('zh-CN', { hour12: false })
              : timeStr();

            const eventType = ev.event_type || '';
            const msg = ev.message || '';
            const details = ev.details || {};

            if (eventType === 'phase_start') {
              const phaseName = details?.phase || msg;
              addLog(`▸ 阶段开始: ${phaseLabel(phaseName)}`, 'phase');
              const desc = PHASE_DESC[phaseName];
              if (desc) addLog(`  ${desc}`, 'phase');
            } else if (eventType === 'phase_complete') {
              const phaseName = details?.phase || msg;
              const dur = details?.duration_seconds > 0 ? formatDuration(details.duration_seconds) : '0秒';
              const findStr = details?.findings > 0 ? ` | 发现 ${details.findings} 个漏洞` : '';
              addLog(`✓ 阶段完成: ${phaseLabel(phaseName)} (${dur}${findStr})`, 'success');
              const resultLines = formatPhaseResult(phaseName, details);
              for (const line of resultLines) addLog(line, 'info');
            } else if (eventType === 'finding') {
              const sev = (details?.severity || 'info').toLowerCase();
              const icon = SEVERITY_ICONS[sev] || '⚪';
              const title = details?.title || details?.vuln_type || msg || '未知漏洞';
              const engine = details?.engine ? ` [${details.engine}]` : '';
              const location = details?.file_path ? `${details.file_path}:${details?.line_start || '?'}` : '';
              addLog(`${icon} [${sev.toUpperCase()}] ${title}${engine}`, 'finding');
              if (location) addLog(`    ${location}`, 'info');
            } else if (eventType === 'progress') {
              if (msg) addLog(`  ${msg}`, 'info');
            } else if (eventType === 'warning') {
              addLog(`⚠ ${msg || '警告'}`, 'warning');
            } else if (eventType === 'scan_complete') {
              addLog('', 'info');
              addLog(`══════════════════════════════════════════════`, 'success');
              addLog(`  ✓ 扫描完成`, 'success');
              const dur = details?.duration_seconds > 0 ? formatDuration(details.duration_seconds) : '0秒';
              addLog(`  耗时: ${dur}`, 'success');
              if (details?.findings_count != null) addLog(`  漏洞: ${details.findings_count} 个`, 'success');
              if (details?.tokens_used > 0) addLog(`  Token: ${details.tokens_used.toLocaleString()}`, 'success');
              if (details?.severity_breakdown) {
                const sb = details.severity_breakdown;
                addLog(`  严重性分布: 🔴${sb.critical ?? 0} 🟠${sb.high ?? 0} 🟡${sb.medium ?? 0} 🟢${sb.low ?? 0} 🔵${sb.info ?? 0}`, 'info');
              }
              addLog(`══════════════════════════════════════════════`, 'success');
            } else if (eventType === 'engine_start') {
              const engineName = details?.engine || ev.engine_name || '';
              if (engineName) {
                addLog(`⚙ 启动引擎: ${engineName.toUpperCase()}`, 'info');
              }
            } else if (eventType === 'engine_complete') {
              const engineName = details?.engine || ev.engine_name || '';
              const findingsCount = details?.findings_count ?? 0;
              const dur = details?.duration_seconds > 0 ? formatDuration(details.duration_seconds) : '';
              const durStr = dur ? `, ${dur}` : '';
              if (engineName) {
                addLog(`✦ ${engineName.toUpperCase()} 完成: ${findingsCount} 个漏洞${durStr}`, 'success');
              }
            } else if (eventType === 'engine_failed') {
              const engineName = details?.engine || ev.engine_name || '';
              addLog(`✗ 引擎 ${engineName.toUpperCase()} 失败: ${msg}`, 'error');
            } else if (eventType === 'adversarial_round') {
              // Reuse the same debate formatting as real-time events
              if (details) {
                const findingTitle = details.finding_title || details.vuln_type || `Finding #${details.finding_id}`;
                const role = details.role || 'unknown';
                const roundNum = details.round || '?';

                if (role === 'attacker') {
                  addLog(`\n🗣 辩论漏洞: ${findingTitle} (${details.severity || ''})`, 'debate');
                }

                const lines = formatDebateRound(details);
                for (let i = 0; i < lines.length; i++) {
                  const detail = (i === 0 && details.detail) ? details.detail : undefined;
                  addLog(lines[i], 'debate', detail);
                }
              }
            } else if (eventType === 'adjudication_result') {
              if (details) {
                const icon = details.final_status === 'confirmed' ? '✓' : details.final_status === 'false_positive' ? '✗' : '?';
                const statusMap: Record<string, string> = {
                  confirmed: '已确认', false_positive: '误报', conditional: '有条件',
                  not_exploitable: '不可利用', informational: '信息级',
                };
                const statusLabel = statusMap[details.final_status] || details.final_status;
                addLog(`  ${icon} 裁决: ${details.finding_title || '未知'} → ${statusLabel}`, 'adjudication', details);
              }
            } else if (eventType === 'verification_result') {
              if (details) {
                const statusMap: Record<string, string> = {
                  confirmed: '已确认', false_positive: '误报', needs_review: '待审查',
                  conditional: '有条件', not_exploitable: '不可利用',
                };
                const statusLabel = statusMap[details.status] || details.status;
                const confidence = details.confidence !== undefined ? ` (${(details.confidence * 100).toFixed(0)}%)` : '';
                addLog(`  🔍 验证: ${details.finding_title || '未知'} → ${statusLabel}${confidence}`, 'verification', details);
              }
            } else if (eventType === 'finding_skipped') {
              if (details) {
                addLog(`  ⏭ 跳过: ${details.finding_title || '未知'} (${details.reason || '未满足验证条件'})`, 'skip');
              }
            } else if (eventType === 'scan_failed') {
              addLog(`\n✗ 扫描失败: ${details?.error || msg || '未知错误'}`, 'error');
            } else if (msg) {
              addLog(`  ${msg}`, 'info');
            }
          }
        } else {
          // No events in DB, show status-only log
          if (scanStatus === 'completed') {
            addLog(`◉ 扫描 #${scanId} 已完成`, 'success');
          } else if (scanStatus === 'failed') {
            addLog(`◉ 扫描 #${scanId} 失败`, 'error');
          } else {
            addLog(`◉ 扫描 #${scanId} ${scanStatus}`, 'info');
          }
        }
      } catch (err) {
        console.error('Failed to load scan events:', err);
        // Fallback to status-only log
        if (scanStatus === 'completed') {
          addLog(`◉ 扫描 #${scanId} 已完成`, 'success');
        } else if (scanStatus === 'failed') {
          addLog(`◉ 扫描 #${scanId} 失败`, 'error');
        }
      }
    };
    loadHistory();
  }, [scanStatus]); // re-fire when scanStatus changes

  const isActive = scanStatus === 'running' || scanStatus === 'pending' || scanStatus === 'paused';
  const showCursor = scanStatus === 'running' || scanStatus === 'pending';

  // --- fullscreen ---
  const toggleFullscreen = useCallback(() => {
    const el = cardRef.current;
    if (!el) return;
    if (!document.fullscreenElement) {
      el.requestFullscreen().catch(() => {});
    } else {
      document.exitFullscreen().catch(() => {});
    }
  }, []);

  useEffect(() => {
    const handler = () => setIsFullscreen(!!document.fullscreenElement);
    document.addEventListener('fullscreenchange', handler);
    return () => document.removeEventListener('fullscreenchange', handler);
  }, []);

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen}>
      <Card ref={cardRef} className={`glass-panel overflow-hidden ${isFullscreen ? 'bg-[#080a10]' : ''}`}>
        {/* Header */}
        <CollapsibleTrigger className="w-full">
          <div className="flex items-center justify-between px-4 py-3 hover:bg-white/[0.02] transition-colors">
            <div className="flex items-center gap-2">
              <Terminal className="h-5 w-5 text-cyan" />
              <h3 className="text-cyan font-mono font-bold">{isActive ? 'TERMINAL' : 'SCAN LOG'}</h3>
              <Badge variant={isActive ? 'running' : 'completed'} className="font-mono text-xs">
                {logs.length}
              </Badge>
            </div>
            <div className="flex items-center gap-3">
              <ConnectionDot state={wsState} />
              <button
                onClick={(e) => { e.stopPropagation(); toggleFullscreen(); }}
                className="p-1 rounded hover:bg-white/10 transition-colors text-text-secondary hover:text-cyan"
                title={isFullscreen ? '退出全屏' : '全屏'}
              >
                {isFullscreen ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
              </button>
              <ChevronDown className={`h-4 w-4 text-text-secondary transition-transform ${isOpen ? '' : '-rotate-90'}`} />
            </div>
          </div>
        </CollapsibleTrigger>

        {/* Terminal body */}
        <CollapsibleContent>
          <div
            ref={containerRef}
            onScroll={handleScroll}
            className={`bg-[#080a10] border-t border-border font-mono text-sm overflow-y-auto custom-scrollbar relative ${isFullscreen ? 'h-[calc(100vh-52px)]' : 'max-h-96'}`}
          >
            {/* Scanline overlay */}
            <div
              className="absolute inset-0 pointer-events-none z-10 opacity-20"
              style={{
                backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.15) 2px, rgba(0,0,0,0.15) 4px)',
              }}
            />

            <div className="relative z-20 p-3 space-y-0.5 pb-10">
              {logs.map(entry => (
                <LogLine key={entry.id} entry={entry} onToggle={toggleDetail} />
              ))}

              {/* Blinking cursor */}
              {showCursor && (
                <div className="flex items-center gap-3 mt-2 px-2">
                  <span className="text-slate-600 text-xs w-20 font-mono select-none">{timeStr()}</span>
                  <span className="text-cyan animate-pulse font-bold">_</span>
                </div>
              )}

              {/* Exit status */}
              {(scanStatus === 'completed' || scanStatus === 'failed' || scanStatus === 'cancelled') && (
                <div className="mt-3 pt-2 border-t border-slate-800">
                  <span className={`text-xs font-mono ${scanStatus === 'completed' ? 'text-emerald-400' : 'text-red-400'}`}>
                    {scanStatus === 'completed' ? '● PROCESS EXITED (0)' : '● PROCESS EXITED (1)'}
                  </span>
                </div>
              )}
            </div>
          </div>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  );
});

export default LiveTerminalInner;
