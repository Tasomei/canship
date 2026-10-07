/**
 * 生成自包含的离线 HTML 报告。内容全部静态写入页面，脚本只负责筛选、分组、复制与打印展开；
 * 内容安全策略禁止加载任何外部资源，内联脚本按哈希放行。
 */

import { createHash } from 'node:crypto'
import type { Finding, ScanResult } from '../types.js'
import { renderFixPrompt } from './prompt.js'
import { fingerprintOf } from '../baseline.js'
import {
  categoryCounts, categoryOf, CATEGORIES, changeViewNotice, groupByFile, locationOf, manualSteps, plural, SEVERITIES,
  skipPhrase, verdictOf,
} from './shared.js'

export interface HtmlOptions {
  root: string
  /** 报告生成时间。 */
  generatedAt: string
  /** 页眉显示的扫描器版本。 */
  version?: string
  /** 默认视图隐藏的疑似结果数。 */
  hiddenLikely?: number
  /** 基线抑制数量；独立报告必须披露这一信息。 */
  baselineSuppressed?: number
  /** 未匹配的基线接受次数。 */
  baselineStale?: number
  baselineExpired?: number
  /** 应用的基线文件路径。 */
  baselinePath?: string | null
}

/** 转义插入 HTML 的文本；所有来自被扫描仓库的内容都必须经过这里。 */
function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/** 逐段渲染并保留段落结构。 */
function paragraphs(parts: string[]): string {
  return parts.map((p) => `<p>${linkify(esc(p.trim()))}</p>`).join('')
}

/** 将已转义文本中的 URL 转为链接。 */
function linkify(html: string): string {
  return html.replace(
    /https?:\/\/[^\s<>"')]+/g,
    (url) => `<a href="${url}" target="_blank" rel="noreferrer noopener">${url}</a>`,
  )
}

/** 嵌入数据块时转义可提前结束脚本元素的字符。 */
function jsonForScript(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(new RegExp(String.fromCharCode(0x2028), 'g'), '\\u2028')
    .replace(new RegExp(String.fromCharCode(0x2029), 'g'), '\\u2029')
}

/** ISO 时间转为分钟精度的 UTC；无法解析时原样显示。 */
function displayTime(iso: string): string {
  const date = new Date(iso)
  if (!iso || Number.isNaN(date.getTime())) return iso
  return `${date.toISOString().slice(0, 16).replace('T', ' ')} UTC`
}

const EVIDENCE_LABEL: Record<NonNullable<Finding['evidence']>[number]['kind'], string> = {
  operation: 'operation',
  import: 'imports',
  'admin-client': 'admin client',
  'auth-helper': 'auth helper',
}

function renderFinding(f: Finding, index: number, anchor: string): string {
  const category = categoryOf(f.ruleId)
  const search = `${f.title} ${f.file ?? ''} ${f.ruleId}`.toLowerCase()
  const trace = f.evidence?.length
    ? `<h3>Trace (static relationships)</h3><ol class="trace">${f.evidence.map(step =>
      `<li><span class="k">${EVIDENCE_LABEL[step.kind]}</span><span class="v">${esc(locationOf(step))}</span><span class="note">${esc(step.description)}</span></li>`).join('')}</ol>${f.evidenceTruncated ? '<p class="faint">Additional dependency steps omitted.</p>' : ''}`
    : ''
  const fix = f.fix.length > 0 ? `<h3>Fix</h3><ol class="steps">${f.fix.map(s => `<li>${linkify(esc(s))}</li>`).join('')}</ol>` : ''
  const hand = f.humanOnly?.length
    ? `<div class="hand"><b>By hand</b><ul>${f.humanOnly.map(s => `<li>${linkify(esc(s))}</li>`).join('')}</ul></div>`
    : ''
  return `<details class="f" id="${anchor}" data-i="${index}" data-sev="${f.severity}" data-cat="${esc(category)}" data-conf="${f.confidence}" data-file="${esc(f.file ?? '')}" data-text="${esc(search)}">
<summary class="row"><span class="sev ${f.severity}">${f.severity}</span><span class="main"><span class="title">${esc(f.title)}</span>${f.confidence === 'likely' ? '<span class="likely">likely</span>' : ''}<span class="loc"><span class="loc-line">${f.line !== null ? `line ${f.line}` : f.file ? 'whole file' : 'repository'}</span><span class="loc-full">${esc(locationOf(f))}</span></span></span><span class="cat">${esc(category)}</span></summary>
<div class="body">
<p class="rule">${esc(f.ruleId)}</p>
${f.excerpt ? `<pre class="excerpt"><code>${esc(f.excerpt)}</code></pre>` : ''}
<div class="why">${paragraphs(f.why)}</div>
${trace}${fix}${hand}
<p class="actions"><button type="button" class="link js-only" data-copy="${index}">copy fix prompt</button><button type="button" class="link js-only" data-copy-ref="${index}">copy reference</button><a class="link" href="#${anchor}" aria-label="Link to this finding">link</a></p>
</div>
</details>`
}

/** 页面脚本：只操作已渲染的元素，不加载任何资源。 */
const SCRIPT = `(function(){
var d=document,b=d.body;b.classList.add('js');
var data={};try{data=JSON.parse(d.getElementById('canship-data').textContent||'{}')}catch(e){}
var rows=[].slice.call(d.querySelectorAll('details.f')),list=d.getElementById('list'),st={sev:null,cat:null,conf:null,q:'',g:'file'};
var SEV=['P0','P1','P2'],CAT=data.categories||[];
function matches(r){return(!st.sev||r.dataset.sev===st.sev)&&(!st.cat||r.dataset.cat===st.cat)&&(!st.conf||r.dataset.conf===st.conf)&&(!st.q||r.dataset.text.indexOf(st.q)>=0)}
function keyOf(r){return st.g==='sev'?r.dataset.sev:st.g==='cat'?r.dataset.cat:r.dataset.file}
function label(k){return st.g==='sev'?k+' \\u00b7 '+({P0:'critical',P1:'high',P2:'medium'})[k]:(k||'repository')}
function render(){
  if(!list)return;
  var groups=[],index=new Map();
  rows.forEach(function(r){var k=keyOf(r);if(!index.has(k)){index.set(k,groups.length);groups.push({k:k,rows:[]})}groups[index.get(k)].rows.push(r)});
  if(st.g==='sev')groups.sort(function(a,c){return SEV.indexOf(a.k)-SEV.indexOf(c.k)});
  if(st.g==='cat')groups.sort(function(a,c){return CAT.indexOf(a.k)-CAT.indexOf(c.k)});
  list.textContent='';var shown=0;
  groups.forEach(function(g){
    var visible=g.rows.filter(matches);if(!visible.length)return;shown+=visible.length;
    var h=d.createElement('div');h.className='group';var name=d.createElement('span');name.className='gk';name.textContent=label(g.k);
    h.appendChild(name);h.appendChild(d.createTextNode(' \\u2014 '+visible.length));list.appendChild(h);
    var box=d.createElement('div');box.className='ledger';visible.forEach(function(r){box.appendChild(r)});list.appendChild(box);
  });
  list.classList.toggle('by-file',st.g==='file');
  var count=d.getElementById('count');if(count)count.textContent=shown+' of '+rows.length+' findings in this report';
  var empty=d.getElementById('empty');if(empty)empty.hidden=shown>0;
  function selected(x,on){x.classList.toggle('on',on);x.setAttribute('aria-pressed',String(on))}
  [].forEach.call(d.querySelectorAll('[data-filter-sev]'),function(x){selected(x,(x.dataset.filterSev||null)===st.sev&&!st.cat)});
  [].forEach.call(d.querySelectorAll('[data-filter-conf]'),function(x){selected(x,(x.dataset.filterConf||null)===st.conf)});
  [].forEach.call(d.querySelectorAll('[data-group]'),function(x){selected(x,x.dataset.group===st.g)});
  [].forEach.call(d.querySelectorAll('[data-mx-cat]'),function(x){selected(x,x.dataset.mxCat===st.cat&&x.dataset.mxSev===st.sev)});
}
[].forEach.call(d.querySelectorAll('[data-filter-sev]'),function(x){x.onclick=function(){st.sev=x.dataset.filterSev||null;st.cat=null;render()}});
[].forEach.call(d.querySelectorAll('[data-filter-conf]'),function(x){x.onclick=function(){st.conf=x.dataset.filterConf||null;render()}});
[].forEach.call(d.querySelectorAll('[data-group]'),function(x){x.onclick=function(){st.g=x.dataset.group;render()}});
[].forEach.call(d.querySelectorAll('[data-mx-cat]'),function(x){x.onclick=function(){var same=st.cat===x.dataset.mxCat&&st.sev===x.dataset.mxSev;st.cat=same?null:x.dataset.mxCat;st.sev=same?null:x.dataset.mxSev;render()}});
var q=d.getElementById('q');if(q)q.oninput=function(){st.q=q.value.toLowerCase();render()};
function clearFilters(){st.sev=null;st.cat=null;st.conf=null;st.q='';if(q)q.value=''}
var clear=d.getElementById('clear');if(clear)clear.onclick=function(){clearFilters();render()};
function copy(text,btn){
  function feedback(message){var t=btn.textContent;btn.textContent=message;setTimeout(function(){btn.textContent=t},1200)}
  function done(){feedback('copied')}
  function fallback(){var previous=d.activeElement,a=d.createElement('textarea');a.value=text;d.body.appendChild(a);a.select();try{if(d.execCommand('copy'))done();else feedback('copy unavailable')}catch(e){feedback('copy unavailable')}finally{d.body.removeChild(a);if(previous&&previous.focus)previous.focus()}}
  try{if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(text).then(done,fallback)}else fallback()}catch(e){fallback()}
}
[].forEach.call(d.querySelectorAll('[data-copy]'),function(x){x.onclick=function(e){e.preventDefault();var t=(data.prompts||{})[x.dataset.copy];if(t)copy(t,x)}});
[].forEach.call(d.querySelectorAll('[data-copy-ref]'),function(x){x.onclick=function(e){e.preventDefault();var t=(data.references||{})[x.dataset.copyRef];if(t)copy(t,x)}});
var store=null;try{store=window.localStorage}catch(e){}
var prefix='canship:'+(data.key||'')+':';
[].forEach.call(d.querySelectorAll('.manual input[type=checkbox]'),function(c){
  try{c.checked=!!store&&store.getItem(prefix+c.dataset.step)==='1'}catch(e){}
  c.closest('li').classList.toggle('done',c.checked);
  c.onchange=function(){c.closest('li').classList.toggle('done',c.checked);try{if(store){if(c.checked)store.setItem(prefix+c.dataset.step,'1');else store.removeItem(prefix+c.dataset.step)}}catch(e){}};
});
var print=d.getElementById('print');if(print)print.onclick=function(){window.print()};
var printState=null;
window.addEventListener('beforeprint',function(){if(printState)return;printState={filters:Object.assign({},st),open:rows.map(function(r){return r.open})};clearFilters();render();rows.forEach(function(r){r.open=true})});
window.addEventListener('afterprint',function(){if(!printState)return;st=printState.filters;if(q)q.value=st.q;rows.forEach(function(r,i){r.open=printState.open[i]});printState=null;render()});
function revealHash(){var hash=window.location&&window.location.hash;if(!hash||!/^#finding-[a-f0-9]{64}(?:-[0-9]+)?$/.test(hash))return;var row=rows.find(function(r){return r.id===hash.slice(1)});if(!row)return;if(!matches(row)){clearFilters();render()}row.open=true;row.scrollIntoView({block:'center'});var summary=row.querySelector('summary');if(summary)summary.focus()}
window.addEventListener('hashchange',revealHash);
render();
revealHash();
})();`

const SCRIPT_HASH = createHash('sha256').update(SCRIPT, 'utf8').digest('base64')

const STYLE = `
:root{color-scheme:light dark;
  --paper:#fcfcfa;--ink:#1b1b18;--ink-2:#5c5b56;--ink-3:#6b6963;--rule:#dddbd3;--rule-2:#bdbab0;--hover:#f3f2ed;
  --p0:#b3261e;--p1:#946200;--p2:#5c5b56;--ok:#2f6b2f;
  --serif:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;
  --code:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{
  --paper:#171715;--ink:#e9e7e0;--ink-2:#a8a69e;--ink-3:#aaa79c;--rule:#2e2d29;--rule-2:#4a4843;--hover:#1f1f1c;
  --p0:#f2877f;--p1:#e0b050;--p2:#a8a69e;--ok:#8fcf8f}}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.6 var(--serif);font-variant-numeric:lining-nums tabular-nums}
button,input{font:inherit;color:inherit;background:none;border:0;padding:0}
a{color:inherit}
button:focus-visible,a:focus-visible,input:focus-visible{outline:2px solid var(--ink);outline-offset:3px}
.page{max-width:1040px;margin:0 auto;padding:28px 32px 80px}
.P0{color:var(--p0)}.P1{color:var(--p1)}.P2{color:var(--p2)}
.faint{color:var(--ink-3)}
.mast{display:flex;justify-content:space-between;align-items:baseline;gap:16px;border-bottom:1px solid var(--ink);padding-bottom:8px;font-size:13.5px}
.mast .root{overflow-wrap:anywhere}
.mast .right{white-space:nowrap}
.link{cursor:pointer;text-decoration:underline;text-decoration-color:var(--rule-2);text-underline-offset:3px;margin-left:16px;color:var(--ink-2)}
.js-only{display:none}.js .js-only{display:inline}
.verdict-block{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:40px;padding:36px 0 30px;border-bottom:1px solid var(--rule)}
h1.verdict{font-weight:400;font-size:44px;line-height:1.08;margin:0 0 12px;letter-spacing:-.01em}
h1.verdict .n{color:var(--p0)}
h1.verdict.warn .n{color:var(--p1)}
h1.verdict.clean{color:var(--ok)}
.verdict-block p{margin:0 0 8px;max-width:58ch;color:var(--ink-2)}
.facts{font-size:13.5px;display:grid;grid-template-columns:auto auto;gap:4px 18px;align-self:end;color:var(--ink-2);margin:0}
.facts dt{color:var(--ink-3)}.facts dd{margin:0;text-align:right;color:var(--ink)}
.notice{color:var(--ink-3);font-size:13.5px;max-width:78ch;margin:14px 0 0}
h2{font-weight:400;font-size:22px;margin:0 0 12px}
.section{padding:28px 0;border-bottom:1px solid var(--rule)}
.section.last{border-bottom:0}
.two{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:48px}
table.matrix{border-collapse:collapse;width:100%}
.matrix th,.matrix td{padding:7px 0;border-bottom:1px solid var(--rule);font-weight:400;text-align:right}
.matrix th{font-size:13.5px;color:var(--ink-3)}
.matrix th:first-child,.matrix td:first-child{text-align:left}
.matrix td button{min-width:28px;text-align:right;cursor:pointer;border-bottom:1px solid transparent}
.matrix td button:hover{border-bottom-color:currentColor}
.matrix td button.on{border-bottom:2px solid currentColor}
.matrix .zero{color:var(--ink-3)}
.matrix tfoot td{border-bottom:0;color:var(--ink-2)}
ol.manual{margin:0;padding:0;list-style:none}
ol.manual li{display:grid;grid-template-columns:24px minmax(0,1fr);align-items:start;gap:8px;padding:6px 0;border-bottom:1px solid var(--rule);font-size:15px}
ol.manual .num{color:var(--ink-3)}
.js ol.manual .num{display:none}
ol.manual input{display:none;margin:5px 0 0;accent-color:var(--ink)}
.js ol.manual input{display:block}
ol.manual li.done .t{color:var(--ink-3);text-decoration:line-through}
ol.manual .src{font-size:13.5px;color:var(--ink-3);overflow-wrap:anywhere}
.controls{display:none;flex-wrap:wrap;align-items:baseline;gap:6px 22px;margin:4px 0 10px;font-size:14px;color:var(--ink-2)}
.js .controls{display:flex}
.controls .lbl{color:var(--ink-3);margin-right:6px}
.controls button{cursor:pointer;margin-right:10px;color:var(--ink-2)}
.controls button.on{color:var(--ink);text-decoration:underline;text-underline-offset:4px;text-decoration-thickness:1.5px}
.controls input{border-bottom:1px solid var(--rule-2);width:200px;padding:2px 0;outline:0}
.controls input:focus{border-bottom-color:var(--ink)}
.controls .clear{margin-left:auto}
#count{color:var(--ink-3);font-size:13.5px;margin:0 0 4px}
.head{display:grid;grid-template-columns:44px minmax(0,1fr) 130px;font-size:13.5px;color:var(--ink-3);padding:6px 0;border-bottom:1px solid var(--ink)}
.group{padding:22px 0 6px;font-size:13.5px;color:var(--ink-3)}
.group .gk{color:var(--ink);font-size:15.5px;overflow-wrap:anywhere}
details.f{border-bottom:1px solid var(--rule);scroll-margin-top:20px}
details.f:target{border-left:2px solid var(--ink);padding-left:8px}
summary.row{display:grid;grid-template-columns:44px minmax(0,1fr) 130px;align-items:start;padding:10px 0;cursor:pointer;list-style:none}
summary.row::-webkit-details-marker{display:none}
summary.row:hover{background:var(--hover)}
summary.row:focus-visible{outline:2px solid var(--ink-2);outline-offset:2px}
.sev{font-weight:600;font-size:14px;padding-left:4px}
.main{min-width:0}
.title{overflow-wrap:anywhere}
.likely{font-size:13.5px;color:var(--ink-3);margin-left:8px}
.loc{display:block;font-size:13.5px;color:var(--ink-2);overflow-wrap:anywhere}
.loc-line{display:none}
.by-file .loc-line{display:inline}.by-file .loc-full{display:none}
.cat{font-size:13.5px;color:var(--ink-3)}
.body{margin:0 0 22px 44px;max-width:740px}
.body p{margin:0 0 12px;color:var(--ink-2)}
.body .rule{font-size:13.5px;color:var(--ink-3)}
.body h3{font-weight:400;font-style:italic;font-size:14px;color:var(--ink-3);margin:18px 0 6px}
pre.excerpt{margin:0 0 14px;padding:8px 10px;background:var(--hover);overflow-x:auto}
code{font-family:var(--code);font-size:12.5px}
ol.trace{margin:0;padding:0;list-style:none;border-left:1px solid var(--rule-2)}
ol.trace li{padding:3px 0 3px 14px;position:relative;font-size:14px}
ol.trace li::before{content:"";position:absolute;left:-4px;top:12px;width:7px;height:7px;border-radius:50%;background:var(--paper);border:1px solid var(--rule-2)}
ol.trace li:first-child::before{background:var(--p0);border-color:var(--p0)}
ol.trace .k{color:var(--ink-3);display:inline-block;width:120px}
ol.trace .v{overflow-wrap:anywhere}
ol.trace .note{display:block;color:var(--ink-3);font-size:13.5px;margin-left:120px}
ol.steps{margin:0;padding-left:20px}
ol.steps li{margin-bottom:6px}
.hand{margin-top:14px;padding-left:12px;border-left:2px solid var(--p1);font-size:15px}
.hand ul{margin:4px 0 0;padding-left:18px}
.actions{margin:14px 0 0;font-size:14px}
.actions .link{margin-left:0}
.actions .link+.link{margin-left:16px}
.incomplete{border-left:2px solid var(--p1);padding-left:14px}
.incomplete ul{margin:0 0 8px;padding-left:18px}
.notes p{margin:0 0 6px;color:var(--ink-2);font-size:14px}
.checked ul{margin:0 0 12px;padding-left:18px;color:var(--ink-2)}
.colophon{margin-top:36px;font-size:13.5px;color:var(--ink-3);max-width:78ch}
@media (max-width:820px){.verdict-block,.two{grid-template-columns:1fr;gap:24px}h1.verdict{font-size:34px}
  summary.row,.head{grid-template-columns:40px minmax(0,1fr)}.cat,.head .c{display:none}.body{margin-left:40px}}
@media print{.controls,.link,#count{display:none!important}body{background:#fff;color:#000}.page{max-width:none;padding:0}}
`

export function renderHtml(result: ScanResult, opts: HtmlOptions): string {
  const { findings } = result
  const hiddenLikely = opts.hiddenLikely ?? 0
  const baselineSuppressed = opts.baselineSuppressed ?? 0
  const baselineStale = opts.baselineStale ?? 0
  const { blocking: visibleBlocking, minor, unsure } = verdictOf(findings)
  const blocking = result.changeView?.totalBlocking ?? visibleBlocking
  const steps = manualSteps(findings)
  const rotations = steps.filter(step => /^Rotate\b/.test(step.text)).length

  // 结论与终端一致；无结果时区分空扫描、未完成、隐藏和基线，避免误报为安全。
  let verdict: string
  let explanation = ''
  if (findings.length > 0) {
    if (blocking > 0) {
      verdict = `<h1 class="verdict bad"><span class="n">${blocking} blocking ${plural(blocking, 'finding')}.</span><br>Do not deploy yet.</h1>`
      explanation = 'Every certain P0 or P1 result below needs a code change.' + (rotations > 0
        ? ` ${rotations} exposed ${plural(rotations, 'credential')} must also be rotated in ${rotations === 1 ? 'its provider' : 'their providers'}; a code change does not revoke ${rotations === 1 ? 'it' : 'them'}.`
        : '')
    } else if (minor > 0) {
      verdict = `<h1 class="verdict warn"><span class="n">${minor} ${plural(minor, 'finding')} to fix.</span><br>Nothing blocking.</h1>`
      explanation = 'No certain P0 or P1 result was found; the findings below are lower severity.'
    } else {
      verdict = `<h1 class="verdict warn"><span class="n">${unsure} ${plural(unsure, 'finding')} to review.</span></h1>`
      explanation = 'These are likely findings: the static evidence is not conclusive, so check each one.'
    }
  } else if (result.filesScanned === 0) {
    verdict = '<h1 class="verdict warn">No files were scanned.<br>Nothing was checked.</h1>'
    explanation = 'canship found no files it could read at this path, so none of its checks ran. This is not a clean result — it is an empty one.'
  } else if (result.partial) {
    verdict = hiddenLikely > 0
      ? `<h1 class="verdict warn">No certain findings — ${hiddenLikely} lower-confidence ${plural(hiddenLikely, 'finding')} hidden, and not everything was checked.</h1>`
      : '<h1 class="verdict warn">No findings — but not everything was checked.</h1>'
  } else if ((result.changeView?.hiddenFindings ?? 0) > 0) {
    verdict = '<h1 class="verdict warn">No visible findings in changed files — other findings still exist.</h1>'
    explanation = 'This view hides existing findings. Re-run without --changed-since for the full report.'
  } else if (hiddenLikely > 0) {
    verdict = `<h1 class="verdict warn">No certain findings — ${hiddenLikely} lower-confidence ${plural(hiddenLikely, 'finding')} hidden.</h1>`
    explanation = `This is not a finding-free result. Re-run with --all --report to include ${hiddenLikely === 1 ? 'it' : 'them'} in the report.`
  } else if (baselineSuppressed > 0) {
    verdict = `<h1 class="verdict warn">No new findings — ${baselineSuppressed} ${plural(baselineSuppressed, 'finding')} accepted by the baseline.</h1>`
    explanation = `This is not a finding-free result. Those problems still exist. Re-run without --baseline to see ${baselineSuppressed === 1 ? 'it' : 'them'}.`
  } else {
    verdict = '<h1 class="verdict clean">No findings in enabled checks.</h1>'
  }

  const facts = [
    ['findings', String(findings.length)],
    ...(hiddenLikely > 0 ? [['likely hidden', String(hiddenLikely)]] : []),
    ['files scanned', String(result.filesScanned)],
    ['coverage', result.partial ? 'incomplete' : 'complete'],
    ['duration', `${result.durationMs} ms`],
  ].map(([k, v]) => `<dt>${k}</dt><dd>${esc(v!)}</dd>`).join('')

  // 汇总表：数字按钮用于筛选，无脚本时仍是普通计数表。
  const rows = categoryCounts(findings)
  const totals = SEVERITIES.map(s => findings.filter(f => f.severity === s).length)
  const matrix = `<table class="matrix"><thead><tr><th></th>${SEVERITIES.map(s => `<th>${s}</th>`).join('')}<th>total</th></tr></thead><tbody>${rows.map(row =>
    `<tr><td>${row.category}</td>${SEVERITIES.map(s => `<td>${row.counts[s]
      ? `<button type="button" class="${s}" data-mx-cat="${row.category}" data-mx-sev="${s}">${row.counts[s]}</button>`
      : '<span class="zero">–</span>'}</td>`).join('')}<td>${row.total}</td></tr>`).join('')}</tbody><tfoot><tr><td>all</td>${totals.map(n => `<td>${n}</td>`).join('')}<td>${findings.length}</td></tr></tfoot></table>`

  const manual = steps.length > 0
    ? `<ol class="manual">${steps.map((step, i) => `<li><span class="num">${i + 1}</span><input type="checkbox" data-step="${i}" aria-label="Mark step ${i + 1} complete: ${esc(step.text)}"><div><div class="t">${linkify(esc(step.text))}</div><div class="src">${esc(step.locations.join(', '))}</div></div></li>`).join('')}</ol>`
    : '<p class="faint">No manual steps for these findings.</p>'

  const groups = groupByFile(findings)
  let index = 0
  const prompts: Record<string, string> = {}
  const references: Record<string, string> = {}
  const occurrences = new Map<string, number>()
  const promptContext = { partial: result.partial, filesScanned: result.filesScanned, hiddenLikely,
    baselineSuppressed, baselineExpired: opts.baselineExpired ?? 0,
    excludedPaths: result.exclusions?.requested ?? [], ignoredFiles: result.ignored,
    silenced: result.ignoredFindings.map(f => `${f.file}:${f.line} (${f.ruleId})`),
    ruleSelection: result.ruleSelection === null ? null : 'a rule filter was applied; review the original report for its scope' }
  const allPrompt = findings.length ? renderFixPrompt(findings, promptContext) : null
  if (allPrompt) prompts['all'] = allPrompt
  const list = groups.map(group => {
    const items = group.findings.map(f => {
      index++
      const prompt = renderFixPrompt([f], promptContext)
      if (prompt) prompts[String(index)] = prompt
      const identity = fingerprintOf(f)
      const occurrence = (occurrences.get(identity) ?? 0) + 1
      occurrences.set(identity, occurrence)
      const anchor = `finding-${identity}${occurrence === 1 ? '' : `-${occurrence}`}`
      references[String(index)] = `${f.ruleId} · ${locationOf(f)}\n#${anchor}`
      return renderFinding(f, index, anchor)
    }).join('\n')
    return `<div class="group"><span class="gk">${esc(group.file ?? 'repository')}</span> — ${group.findings.length}</div><div class="ledger">${items}</div>`
  }).join('\n')

  const findingsSection = findings.length > 0 ? `
<section class="section two">
<div><h2>By category</h2>${matrix}</div>
<div><h2>Manual steps</h2>${manual}</div>
</section>
<section class="section last">
<h2>Findings</h2>
<div class="controls">
<span role="group" aria-label="Severity"><span class="lbl">severity</span><button type="button" data-filter-sev="">all</button>${SEVERITIES.map(s => `<button type="button" data-filter-sev="${s}">${s}</button>`).join('')}</span>
<span role="group" aria-label="Confidence"><span class="lbl">confidence</span><button type="button" data-filter-conf="">all</button><button type="button" data-filter-conf="certain">certain</button><button type="button" data-filter-conf="likely">likely</button></span>
<span role="group" aria-label="Group findings"><span class="lbl">group by</span><button type="button" data-group="file">file</button><button type="button" data-group="sev">severity</button><button type="button" data-group="cat">category</button></span>
<input id="q" type="search" placeholder="filter by text or path" aria-label="Filter findings">
<button type="button" class="clear" id="clear">clear filters</button>
</div>
<p id="count" role="status" aria-live="polite"></p>
<div class="head"><span>sev</span><span>finding</span><span class="c">category</span></div>
<div id="list" class="by-file">${list}</div>
<p id="empty" class="faint" hidden>No findings match these filters.</p>
</section>` : `
<section class="section last checked">
<h2>Scan scope</h2>
<p>${result.ruleSelection === null ? 'All built-in rule groups enabled.' : 'Only the selected rule groups were enabled; see the selection below.'}</p>
<p><strong>No findings means no matches in the selected scope — not that your app is secure.</strong> Checks are bounded and syntax-based. Request-input analysis stays within supported handlers; business authorisation, rate limiting and dependency vulnerabilities are not verified. Rule selection and exclusions are disclosed below.</p>
</section>`

  // 无论是否发现问题，都披露未检查的内容。
  const incomplete = result.partial ? `
<section class="section incomplete">
<h2>Not everything was checked</h2>
<ul>
${result.filesScanned === 0 ? '<li>no files could be read at this path, so every file-based check was skipped</li>' : ''}
${result.errors.map(e => `<li>the <code>${esc(e.ruleId)}</code> check ${e.kind === 'incomplete' ? 'did not finish' : 'failed'}${e.file ? ` on <code>${esc(e.file)}</code>` : ''} — ${esc(e.message)}</li>`).join('\n')}
${result.skipped.map(s => `<li><code>${esc(s.path)}</code> — ${esc(skipPhrase(s.reason))}${s.detail ? ` (${esc(s.detail)})` : ''}</li>`).join('\n')}
</ul>
<p>Anything could be in what was skipped. Re-run once it is readable.</p>
</section>` : ''

  const selection = result.ruleSelection
  const notes = [
    result.exclusions?.requested.length ? `Path exclusions in force: ${result.exclusions.requested.map(path => `<code>${esc(path)}</code>`).join(', ')}. ${result.exclusions.matched.length} exclusion paths matched; matching subtrees and environment history were not checked.` : '',
    hiddenLikely > 0 && findings.length > 0
      ? `${hiddenLikely} lower-confidence ${plural(hiddenLikely, 'finding')} hidden. Re-run with <code>--all --report</code> to include ${hiddenLikely === 1 ? 'it' : 'them'}.` : '',
    baselineSuppressed > 0
      ? `${baselineSuppressed} ${plural(baselineSuppressed, 'finding')} hidden by the baseline${opts.baselinePath ? ` (<code>${esc(opts.baselinePath)}</code>)` : ''}. Those problems still exist.` : '',
    baselineStale > 0
      ? `${baselineStale} baseline ${baselineStale === 1 ? 'entry' : 'entries'} no longer ${baselineStale === 1 ? 'matches' : 'match'} anything — inspect <code>--baseline-review</code> before <code>--baseline-prune</code>.` : '',
    (opts.baselineExpired ?? 0) > 0 ? `${opts.baselineExpired} baseline acceptances expired; expired records no longer suppress findings.` : '',
    result.ignoredFindings.length > 0
      ? `${result.ignoredFindings.length} ${plural(result.ignoredFindings.length, 'finding')} silenced by <code>canship-ignore-next-line</code>: ${result.ignoredFindings.map(f => `<code>${esc(f.file)}:${f.line}</code> (${esc(f.ruleId)})`).join(', ')}` : '',
    selection === null ? '' : `Rule selection in force: ${selection.only.length > 0
      ? `only <code>${selection.only.map(esc).join('</code>, <code>')}</code>`
      : `everything except <code>${selection.skip.map(esc).join('</code>, <code>')}</code>`}${selection.removed > 0 ? `, hiding ${selection.removed} ${plural(selection.removed, 'finding')}` : ''}.`,
    result.ignored.length > 0
      ? `${result.ignored.length} ${plural(result.ignored.length, 'file')} excluded by <code>canship-ignore-file</code>: ${result.ignored.map(f => `<code>${esc(f)}</code>`).join(', ')}` : '',
    result.vendored > 0
      ? `${result.vendored} ${plural(result.vendored, 'file')} skipped inside dependency directories.` : '',
  ].filter(Boolean)

  const data = { key: createHash('sha256').update(`${opts.root}\0${opts.generatedAt}`).digest('hex').slice(0, 16),
    categories: CATEGORIES, prompts, references }

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-${SCRIPT_HASH}'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>canship report</title>
<style>${STYLE}</style>
</head>
<body>
<div class="page">
<header class="mast"><span class="root"><b>canship</b>${opts.version ? ` ${esc(opts.version)}` : ''} · ${esc(opts.root)}</span><span class="right">${esc(displayTime(opts.generatedAt))}${allPrompt ? '<button type="button" class="link js-only" data-copy="all">copy fix prompt</button>' : ''}<button type="button" class="link js-only" id="print">print</button></span></header>
<section class="verdict-block">
<div>${verdict}${explanation ? `<p>${esc(explanation)}</p>` : ''}${result.changeView ? `<p>${esc(changeViewNotice(result.changeView))}</p>` : ''}
<p class="notice">Credential values canship recognises are masked in this report. One in a format it has no pattern for can still appear inside a quoted line, and this report lists your file paths and project structure either way — so treat it as internal, shareable with your team rather than something to post publicly.</p></div>
<dl class="facts">${facts}</dl>
</section>
${findingsSection}
${incomplete}
${notes.length > 0 ? `<section class="section last notes">${notes.map(n => `<p>${n}</p>`).join('')}</section>` : ''}
<p class="colophon">Generated by canship. Everything ran locally; nothing was uploaded. Findings describe static evidence in this repository; they do not verify deployed configuration, credential validity or business authorisation.</p>
</div>
<script type="application/json" id="canship-data">${jsonForScript(data)}</script>
<script>${SCRIPT}</script>
</body>
</html>
`
}
